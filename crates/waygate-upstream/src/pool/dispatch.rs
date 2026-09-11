//! The pool's `tools/call` dispatch surface over the full MRTR response
//! union (SEP-2322): the traced wrapper both `UpstreamCatalog` entry points
//! share, the complete-only guard for the legacy entry point, and the
//! per-call dial's capability mirror. The dispatch body itself
//! (`call_tool_inner`) stays in `pool/mod.rs` beside the checkout/lane
//! machinery it drives.

use std::time::Instant;

use rmcp::model::RequestParamsMeta;
use rmcp::model::{
    CallToolRequest, CallToolRequestParams, CallToolResponse, CallToolResult, ClientCapabilities,
    ClientRequest, ProtocolVersion, ServerResult,
};
use rmcp::service::{PeerRequestOptions, RunningService, ServiceError};
use rmcp::{ErrorData as McpError, RoleClient};
use serde_json::{Map, Value};

use waygate_mcp::catalog::{
    CallScopedResourceReader, CallToolResultProcessing, CallToolResultProcessingError,
    CallToolResultProcessor, InvocationContractIdentity, InvocationError, ToolCallMrtr,
};
use waygate_oidc::Principal;
use waygate_telemetry::metrics::{
    record_upstream_call, record_upstream_call_failure, record_upstream_safe_retry, UpstreamOutcome,
};

use super::{UpstreamErrorClass, UpstreamPool};

#[derive(Debug)]
pub(super) enum ProcessedCallToolResponse {
    Response(CallToolResponse),
    ProcessingError(CallToolResultProcessingError),
}

pub(super) struct ToolCallDispatchOptions<'a> {
    pub(super) mrtr: ToolCallMrtr,
    pub(super) processor: Option<&'a dyn CallToolResultProcessor>,
}

/// Closed lifecycle phases for failures on the upstream leg. The phase is safe
/// to expose to callers and metrics; the underlying error is log-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ToolCallFailurePhase {
    Dial,
    Initialize,
    PreDispatch,
    DispatchedKnownRefusal,
    DispatchedUnknownOutcome,
}

#[derive(Debug)]
pub(super) struct ToolCallAttemptError {
    pub(super) phase: ToolCallFailurePhase,
    pub(super) source: ServiceError,
    pub(super) retryable: bool,
}

impl ToolCallAttemptError {
    pub(super) fn error_class(&self) -> UpstreamErrorClass {
        match self.source {
            ServiceError::Timeout { .. } | ServiceError::Cancelled { .. } => {
                UpstreamErrorClass::Timeout
            }
            ServiceError::McpError(_) | ServiceError::UnexpectedResponse => {
                UpstreamErrorClass::Protocol
            }
            _ => UpstreamErrorClass::Transport,
        }
    }
}

impl ToolCallFailurePhase {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Dial => "dial",
            Self::Initialize => "initialize",
            Self::PreDispatch => "pre_dispatch",
            Self::DispatchedKnownRefusal => "dispatched_known_refusal",
            Self::DispatchedUnknownOutcome => "dispatched_unknown_outcome",
        }
    }

    pub(super) const fn dispatch_proven_absent(self) -> bool {
        matches!(self, Self::Dial | Self::Initialize | Self::PreDispatch)
    }

    pub(super) fn from_dial_error(error: &crate::transport::DialError) -> Self {
        match error {
            crate::transport::DialError::Init(_)
            | crate::transport::DialError::HandshakeTimeout(_) => Self::Initialize,
            _ => Self::Dial,
        }
    }

    pub(super) fn from_service_error(error: &ServiceError) -> Self {
        if matches!(error, ServiceError::McpError(_)) {
            Self::DispatchedKnownRefusal
        } else {
            Self::DispatchedUnknownOutcome
        }
    }
}

/// Send exactly one tool request while preserving the only retry-safety seam
/// the SDK can prove: failure before its request handle is accepted means the
/// request never entered the transport worker. Any later transport failure has
/// an unknown outcome and must not be replayed.
pub(super) async fn call_tool_once_classified(
    service: &RunningService<RoleClient, rmcp::model::ClientInfo>,
    params: CallToolRequestParams,
    timeout: Option<std::time::Duration>,
) -> Result<CallToolResponse, ToolCallAttemptError> {
    let request = ClientRequest::CallToolRequest(CallToolRequest::new(params));
    let deadline = timeout.and_then(|duration| tokio::time::Instant::now().checked_add(duration));
    let options = timeout.map_or_else(PeerRequestOptions::no_options, |duration| {
        PeerRequestOptions::with_timeout(duration).with_max_total_timeout(duration)
    });
    let send = service.peer().send_cancellable_request(request, options);
    let handle = match timeout {
        Some(duration) => {
            tokio::time::timeout(duration, send)
                .await
                .map_err(|_| ToolCallAttemptError {
                    phase: ToolCallFailurePhase::PreDispatch,
                    source: ServiceError::Timeout { timeout: duration },
                    retryable: false,
                })?
        }
        None => send.await,
    }
    .map_err(|source| ToolCallAttemptError {
        phase: ToolCallFailurePhase::PreDispatch,
        source,
        retryable: false,
    })?;
    let response = handle.await_response();
    let result = match deadline {
        Some(deadline) => {
            let remaining = deadline
                .checked_duration_since(tokio::time::Instant::now())
                .unwrap_or_default();
            tokio::time::timeout(remaining, response)
                .await
                .map_err(|_| ToolCallAttemptError {
                    phase: ToolCallFailurePhase::DispatchedUnknownOutcome,
                    source: ServiceError::Timeout {
                        timeout: timeout.unwrap_or_default(),
                    },
                    retryable: false,
                })?
        }
        None => response.await,
    }
    .map_err(|source| ToolCallAttemptError {
        phase: ToolCallFailurePhase::from_service_error(&source),
        source,
        retryable: false,
    })?;
    match result {
        ServerResult::CallToolResult(result) => Ok(CallToolResponse::Complete(result)),
        ServerResult::InputRequiredResult(result) => Ok(CallToolResponse::InputRequired(result)),
        ServerResult::CreateTaskResult(result) => Ok(CallToolResponse::Task(result)),
        _ => Err(ToolCallAttemptError {
            phase: ToolCallFailurePhase::DispatchedUnknownOutcome,
            source: ServiceError::UnexpectedResponse,
            retryable: false,
        }),
    }
}

pub(super) fn admitted_safe_retry(
    admitted: Option<&InvocationContractIdentity>,
    has_continuation: bool,
    approval_gated: bool,
) -> bool {
    !has_continuation
        && !approval_gated
        && admitted.is_some_and(|identity| {
            !identity.side_effects
                && identity.requires_approval_known
                && !identity.requires_approval
        })
}

pub(super) fn call_trace_id() -> String {
    waygate_telemetry::correlation::current_trace_id()
        .unwrap_or_else(|| uuid::Uuid::new_v4().simple().to_string())
}

pub(super) fn bounded_upstream_error(
    server: &str,
    phase: ToolCallFailurePhase,
    retryable: bool,
    attempts: usize,
    trace_id: &str,
) -> McpError {
    McpError::internal_error(
        format!(
            "upstream `{server}` call failed during {}; use trace_id to investigate",
            phase.as_str()
        ),
        Some(serde_json::json!({
            "error": "upstream_call_failed",
            "phase": phase.as_str(),
            "retryable": retryable,
            "attempts": attempts,
            "trace_id": trace_id,
        })),
    )
}

pub(super) fn record_retry_attempt(server: &str) {
    record_upstream_safe_retry(server, "attempted");
}

pub(super) fn record_retry_recovered(server: &str) {
    record_upstream_safe_retry(server, "recovered");
}

pub(super) fn record_retry_exhausted(server: &str) {
    record_upstream_safe_retry(server, "exhausted");
}

pub(super) fn record_failure(server: &str, phase: ToolCallFailurePhase) {
    record_upstream_call_failure(server, phase.as_str());
}

pub(super) struct CallLaneGuard<'a> {
    slot: &'a super::ConnectionSlot,
    isolation: crate::SessionIsolation,
    connection: tokio::sync::RwLockReadGuard<'a, Option<super::Connection>>,
}

pub(super) struct CallAttemptContext<'a> {
    pub(super) attempts: usize,
    pub(super) trace_id: &'a str,
}

impl<'a> CallLaneGuard<'a> {
    pub(super) fn new(
        slot: &'a super::ConnectionSlot,
        isolation: crate::SessionIsolation,
        connection: tokio::sync::RwLockReadGuard<'a, Option<super::Connection>>,
    ) -> Self {
        Self {
            slot,
            isolation,
            connection,
        }
    }
}

pub(super) async fn process_call_response(
    response: Result<CallToolResponse, ToolCallAttemptError>,
    processor: Option<&dyn CallToolResultProcessor>,
    reader: &dyn CallScopedResourceReader,
) -> Result<ProcessedCallToolResponse, ToolCallAttemptError> {
    match (processor, response?) {
        (Some(processor), CallToolResponse::Complete(result)) => {
            Ok(match processor.process(result, reader).await {
                Ok(result) => {
                    ProcessedCallToolResponse::Response(CallToolResponse::Complete(result))
                }
                Err(error) => ProcessedCallToolResponse::ProcessingError(error),
            })
        }
        (_, response) => Ok(ProcessedCallToolResponse::Response(response)),
    }
}

pub(super) async fn finish_call_response(
    pool: &UpstreamPool,
    server: &str,
    entry: &std::sync::Arc<super::UpstreamEntry>,
    lane: CallLaneGuard<'_>,
    permit: crate::breaker::Permit<'_>,
    result: Result<ProcessedCallToolResponse, ToolCallAttemptError>,
    attempt_context: CallAttemptContext<'_>,
) -> Result<ProcessedCallToolResponse, McpError> {
    let CallAttemptContext { attempts, trace_id } = attempt_context;
    let CallLaneGuard {
        slot,
        isolation,
        connection: conn_guard,
    } = lane;
    match result {
        Ok(ProcessedCallToolResponse::Response(out)) => {
            if attempts > 1 {
                record_retry_recovered(server);
            }
            let recovered = permit.success();
            drop(conn_guard);
            pool.settle_probe_recovery(server, entry, recovered).await;
            Ok(ProcessedCallToolResponse::Response(out))
        }
        Ok(ProcessedCallToolResponse::ProcessingError(error)) => {
            if error.upstream_failure() {
                if attempts > 1 {
                    record_retry_exhausted(server);
                }
                permit.failure();
                drop(conn_guard);
                if matches!(isolation, crate::SessionIsolation::Reuse) {
                    pool.mark_slot_down(server, entry, slot, UpstreamErrorClass::Protocol)
                        .await;
                } else {
                    entry.record_runtime_failure(UpstreamErrorClass::Protocol);
                }
            } else {
                if attempts > 1 {
                    record_retry_recovered(server);
                }
                let recovered = permit.success();
                drop(conn_guard);
                pool.settle_probe_recovery(server, entry, recovered).await;
            }
            Ok(ProcessedCallToolResponse::ProcessingError(error))
        }
        Err(error) => {
            let phase = error.phase;
            let error_class = error.error_class();
            record_failure(server, phase);
            if matches!(phase, ToolCallFailurePhase::DispatchedKnownRefusal) {
                if attempts > 1 {
                    record_retry_recovered(server);
                }
                let recovered = permit.success();
                drop(conn_guard);
                pool.settle_probe_recovery(server, entry, recovered).await;
                tracing::info!(%server, %trace_id, phase = phase.as_str(), error = %error.source, "upstream returned an MCP refusal");
                if let ServiceError::McpError(upstream_error) = error.source {
                    // An application refusal is an intentional protocol
                    // response. Preserve its typed code/message/data contract;
                    // only transport/setup failures use the bounded gateway
                    // envelope below.
                    return Err(upstream_error);
                }
                return Err(bounded_upstream_error(
                    server, phase, false, attempts, trace_id,
                ));
            }
            if attempts > 1 {
                record_retry_exhausted(server);
            }
            permit.failure();
            drop(conn_guard);
            // A transport error makes this lane suspect. For `Reuse`, fault
            // this slot so the next periodic probe reconnects it. `PerCall`
            // already dropped its ephemeral connection; MCP application
            // errors are successful transport responses.
            if matches!(isolation, crate::SessionIsolation::Reuse) {
                pool.mark_slot_down(server, entry, slot, error_class).await;
            } else {
                entry.record_runtime_failure(error_class);
            }
            tracing::warn!(%server, %trace_id, phase = phase.as_str(), error = %error.source, "upstream call failed after dispatch may have occurred");
            Err(bounded_upstream_error(
                server,
                phase,
                error.retryable,
                attempts,
                trace_id,
            ))
        }
    }
}

impl UpstreamPool {
    // Upstream leg of the call: semconv span name `tools/call`, `otel.kind` =
    // `client` (the gateway is the MCP client here), plus `mcp.method.name` /
    // `gen_ai.tool.name`. `mcp.server` is gateway-specific (no semconv
    // equivalent for the upstream name) and `upstream.outcome` is retained;
    // both pre-semconv `mcp.tool` and the new `gen_ai.tool.name` are emitted
    // during the dual-emit window.
    #[tracing::instrument(
        name = "tools/call",
        skip(self, args, principal, mrtr),
        fields(
            mcp.server = %server,
            mcp.method.name = "tools/call",
            mcp.tool = %tool_name,
            gen_ai.tool.name = %tool_name,
            otel.kind = "client",
            error.type = tracing::field::Empty,
            upstream.outcome = tracing::field::Empty,
        ),
    )]
    pub(super) async fn call_tool_traced(
        &self,
        server: &str,
        tool_name: &str,
        args: Option<Map<String, Value>>,
        principal: Option<&Principal>,
        admitted: Option<&InvocationContractIdentity>,
        mrtr: ToolCallMrtr,
    ) -> Result<CallToolResponse, McpError> {
        let started = Instant::now();
        let result = self
            .call_tool_inner(
                server,
                tool_name,
                args,
                principal,
                admitted,
                ToolCallDispatchOptions {
                    mrtr,
                    processor: None,
                },
            )
            .await
            .and_then(|response| match response {
                ProcessedCallToolResponse::Response(response) => Ok(response),
                ProcessedCallToolResponse::ProcessingError(_) => Err(McpError::internal_error(
                    "call result processing ran without a processor",
                    None,
                )),
            });

        // An `input_required` pause is a successful upstream round trip —
        // the upstream answered exactly as the protocol allows — so it
        // classifies as `Ok` for the breaker-adjacent outcome metric and
        // carries no `error.type`.
        let outcome = match &result {
            Ok(_) => UpstreamOutcome::Ok,
            Err(e) if e.message.contains("is not connected") => UpstreamOutcome::NotConnected,
            Err(_) => UpstreamOutcome::Error,
        };
        let outcome_str = match outcome {
            UpstreamOutcome::Ok => "ok",
            UpstreamOutcome::Error => "error",
            UpstreamOutcome::NotConnected => "not_connected",
        };
        tracing::Span::current().record("upstream.outcome", outcome_str);
        // OTel semconv `error.type` (shared with the inbound server span):
        // `tool_error` / JSON-RPC code / unset. Complements the
        // gateway-specific `upstream.outcome` above.
        if let Some(et) = waygate_mcp::protocol::tool_call_response_error_type(&result) {
            tracing::Span::current().record("error.type", et.as_str());
        }
        record_upstream_call(server, outcome, started.elapsed().as_secs_f64());

        result
    }

    #[tracing::instrument(
        name = "tools/call",
        skip(self, args, principal, processing),
        fields(
            mcp.server = %server,
            mcp.method.name = "tools/call",
            mcp.tool = %tool_name,
            gen_ai.tool.name = %tool_name,
            otel.kind = "client",
            error.type = tracing::field::Empty,
            upstream.outcome = tracing::field::Empty,
        ),
    )]
    pub(super) async fn call_tool_traced_processed(
        &self,
        server: &str,
        tool_name: &str,
        args: Option<Map<String, Value>>,
        principal: Option<&Principal>,
        admitted: Option<&InvocationContractIdentity>,
        processing: CallToolResultProcessing<'_>,
    ) -> Result<CallToolResponse, InvocationError> {
        let started = Instant::now();
        let CallToolResultProcessing { mrtr, processor } = processing;
        let result = self
            .call_tool_inner(
                server,
                tool_name,
                args,
                principal,
                admitted,
                ToolCallDispatchOptions {
                    mrtr,
                    processor: Some(processor),
                },
            )
            .await;

        let outcome = match &result {
            Ok(ProcessedCallToolResponse::Response(_)) => UpstreamOutcome::Ok,
            Ok(ProcessedCallToolResponse::ProcessingError(error)) if error.upstream_failure() => {
                UpstreamOutcome::Error
            }
            Ok(ProcessedCallToolResponse::ProcessingError(_)) => UpstreamOutcome::Ok,
            Err(error) if error.message.contains("is not connected") => {
                UpstreamOutcome::NotConnected
            }
            Err(_) => UpstreamOutcome::Error,
        };
        let outcome_str = match outcome {
            UpstreamOutcome::Ok => "ok",
            UpstreamOutcome::Error => "error",
            UpstreamOutcome::NotConnected => "not_connected",
        };
        tracing::Span::current().record("upstream.outcome", outcome_str);
        match &result {
            Ok(ProcessedCallToolResponse::Response(CallToolResponse::Complete(result)))
                if result.is_error == Some(true) =>
            {
                tracing::Span::current().record("error.type", "tool_error");
            }
            Ok(ProcessedCallToolResponse::ProcessingError(_)) => {
                tracing::Span::current().record("error.type", "result_processing_error");
            }
            Err(error) => {
                tracing::Span::current().record("error.type", error.code.0.to_string());
            }
            _ => {}
        }
        record_upstream_call(server, outcome, started.elapsed().as_secs_f64());

        match result {
            Ok(ProcessedCallToolResponse::Response(response)) => Ok(response),
            Ok(ProcessedCallToolResponse::ProcessingError(error)) => Err(error.into_error()),
            Err(error) => Err(InvocationError::Upstream(error)),
        }
    }
}

/// Unwrap the complete result for the legacy `call_tool` entry point, which
/// dispatches with no caller input capabilities: the dial advertises
/// nothing, so a conforming upstream completes in one round — a pause or
/// task envelope anyway is an upstream contract violation, refused here.
pub(super) fn require_complete(
    response: CallToolResponse,
    server: &str,
    tool_name: &str,
) -> Result<CallToolResult, McpError> {
    match response {
        CallToolResponse::Complete(result) => Ok(result),
        _ => Err(McpError::internal_error(
            format!(
                "upstream `{server}` returned a non-final response for `{tool_name}` \
                 although this dispatch declared no input capabilities"
            ),
            None,
        )),
    }
}

/// Assemble the upstream `tools/call` params for one dispatch.
///
/// The MRTR retry payload (SEP-2322) — the caller's answers and the
/// upstream's opaque `requestState` — is forwarded exactly as received; the
/// gateway neither inspects nor rewrites it. W3C trace context rides
/// `params._meta` so the upstream continues this trace (OTel MCP semconv);
/// injection writes nothing when no tracer provider is installed.
pub(super) fn build_call_params(
    tool_name: &str,
    args: Option<Map<String, Value>>,
    input_responses: Option<rmcp::model::InputResponses>,
    request_state: Option<String>,
) -> rmcp::model::CallToolRequestParams {
    let mut params = rmcp::model::CallToolRequestParams::new(tool_name.to_owned());
    if let Some(a) = args {
        params = params.with_arguments(a);
    }
    if let Some(responses) = input_responses {
        params = params.with_input_responses(responses);
    }
    if let Some(state) = request_state {
        params = params.with_request_state(state);
    }
    let mut meta = rmcp::model::RequestMetaObject::new();
    waygate_telemetry::propagation::inject_span(&tracing::Span::current(), &mut meta.0);
    if !meta.0.is_empty() {
        params.set_meta(meta);
    }
    params
}

/// The manifest half of the continuation generation binding, for the
/// per-call path: an upstream whose configuration can never negotiate
/// 2026-07-28 — `protocol: legacy` (the operator's escape hatch) or the
/// SSE transport (legacy by definition) — can never have issued the pause
/// a continuation answers, so a continuation aimed at it is refused with a
/// teach-through. Refusal, not override: caller-supplied retry fields must
/// never force a lifecycle the operator disabled, and pinning is reserved
/// for narrowing `auto` (which already permits 2026) in
/// [`per_call_dial`]. `None` admits the dispatch.
pub(super) fn manifest_continuation_refusal(
    server: &str,
    has_continuation: bool,
    manifest: &crate::UpstreamManifest,
) -> Option<McpError> {
    if !has_continuation {
        return None;
    }
    let cannot_negotiate_2026 = matches!(manifest.transport, crate::Transport::Sse)
        || manifest.protocol == crate::UpstreamProtocol::Legacy;
    if !cannot_negotiate_2026 {
        return None;
    }
    Some(McpError::internal_error(
        format!(
            "upstream `{server}` is configured for the legacy protocol generation and cannot \
             have issued an MRTR pause; the continuation cannot be delivered — retry the call \
             from the beginning without `inputResponses`/`requestState`"
        ),
        None,
    ))
}

/// The reuse-lane half of the continuation generation binding: a retry's
/// `inputResponses`/`requestState` answer a pause only a 2026 leg can have
/// issued, and a legacy upstream would silently ignore them — so a
/// continuation on a lane that no longer speaks 2026 (e.g. after a
/// reconnect during an upstream rollback) is refused with a teach-through
/// instead of dispatching fields the leg cannot honor. `None` admits the
/// dispatch. The per-call half of the same binding is the pinned dial in
/// [`per_call_dial`].
pub(super) fn legacy_continuation_refusal(
    server: &str,
    has_continuation: bool,
    negotiated_protocol: Option<&str>,
) -> Option<McpError> {
    let lane_is_2026 = negotiated_protocol
        .is_some_and(|version| version >= ProtocolVersion::V_2026_07_28.as_str());
    if !has_continuation || lane_is_2026 {
        return None;
    }
    Some(McpError::internal_error(
        format!(
            "upstream `{server}` lane no longer speaks MCP 2026-07-28; the MRTR continuation \
             cannot be delivered — retry the call from the beginning"
        ),
        None,
    ))
}

/// The capability mirror decision for a per-call ephemeral dial:
/// `Some(capabilities)` to mirror, `None` for an ordinary
/// no-capabilities dial.
///
/// Mirrors the downstream caller's declared elicitation capability — the
/// one input-request kind the gateway relays — into this call's own dial:
/// the SDK fixes capabilities per dial, and this dial is per-caller, so the
/// upstream sees exactly which pauses the caller can answer and issues an
/// MRTR pause only when the round trip can complete. Nothing else is
/// mirrored: sampling and roots are deprecated in MCP 2026-07-28 and the
/// repo's deprecation posture builds no passthrough for them, and
/// extension declarations (e.g. the SEP-2663 tasks extension) and
/// experimental capabilities are the caller's contract with the *gateway* —
/// advertising any of these upstream would invite responses (a sampling
/// pause, a task envelope) that the dispatch pipeline must refuse.
///
/// The decision reads the boot lane's negotiated generation, but each dial
/// negotiates independently under `protocol: auto` — so the caller MUST
/// pair a `Some` result with a dial pinned to 2026-07-28
/// ([`pinned_2026_manifest`]): if the upstream rolled back to legacy since
/// the boot lane dialed, the pinned dial fails loud instead of running a
/// legacy leg mid-round-trip. That matters even when the mirrored set is
/// EMPTY — a 2026 caller with no declared input-request capabilities can
/// still receive and echo a state-only pause, so its round trip needs the
/// same generation guarantee (an empty mirror on a legacy handshake would
/// be harmless, but a state-only continuation against a legacy leg is
/// not). `None` only when the caller cannot receive pauses at all or the
/// boot lane is legacy (a legacy upstream never pauses, so there is no
/// round trip to protect). Shared dials (boot/catalog lanes, reuse lanes)
/// never call this and keep the default empty set.
pub(super) fn mirrored_dial_capabilities(
    caller: Option<&ClientCapabilities>,
    negotiated_protocol: Option<&str>,
) -> Option<ClientCapabilities> {
    let caps = caller?;
    let version = negotiated_protocol?;
    if version < ProtocolVersion::V_2026_07_28.as_str() {
        return None;
    }
    let mut mirrored = ClientCapabilities::default();
    mirrored.elicitation = caps.elicitation.clone();
    Some(mirrored)
}

/// The manifest a capability-mirroring ephemeral dial must use: the same
/// shape, with `protocol` pinned to 2026-07-28 so the dial never falls
/// back to a legacy handshake while declaring mirrored capabilities (see
/// [`mirrored_dial_capabilities`]). A rolled-back upstream fails this dial
/// — counted against the breaker, healed by the ordinary re-probe — rather
/// than receiving a capability-bearing legacy `initialize`.
pub(super) fn pinned_2026_manifest(snapshot: &crate::UpstreamManifest) -> crate::UpstreamManifest {
    let mut pinned = snapshot.clone();
    pinned.protocol = crate::UpstreamProtocol::V20260728;
    pinned
}

/// Dial the per-call ephemeral session, mirroring the caller's declared
/// elicitation capability when [`mirrored_dial_capabilities`] admits it.
/// The dial is pinned to the 2026 generation ([`pinned_2026_manifest`])
/// when it mirrors OR when the call carries MRTR continuation fields — a
/// retry answers a pause only a 2026 leg can have issued, and a legacy leg
/// would silently ignore its `inputResponses`/`requestState`, so an
/// upstream rollback fails the pinned dial loud instead of dispatching
/// the continuation onto a leg that cannot honor it.
///
/// The pin only ever narrows `protocol: auto` (which already permits
/// 2026): the caller must have screened manifests that cannot negotiate
/// 2026 at all via [`manifest_continuation_refusal`] first, so
/// caller-supplied retry fields can never force a lifecycle the operator
/// disabled. A dial that neither mirrors nor continues is the ordinary
/// no-capabilities dial on the manifest's own lifecycle.
pub(super) async fn per_call_dial(
    snapshot: &crate::UpstreamManifest,
    issuer: Option<&waygate_oidc::SharedIdentityIssuer>,
    cell: Option<&crate::identity_client::IdentityCell>,
    exchange: Option<&super::ExchangeBundle>,
    caller: Option<&ClientCapabilities>,
    negotiated_protocol: Option<&str>,
    has_continuation: bool,
) -> Result<
    rmcp::service::RunningService<rmcp::RoleClient, rmcp::model::ClientInfo>,
    crate::transport::DialError,
> {
    let mirrored = mirrored_dial_capabilities(caller, negotiated_protocol);
    if mirrored.is_none() && !has_continuation {
        return crate::transport::connect(snapshot, issuer, cell, exchange).await;
    }
    crate::transport::connect_with_capabilities(
        &pinned_2026_manifest(snapshot),
        issuer,
        cell,
        exchange,
        mirrored.unwrap_or_default(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::{ClientInfo, Implementation};
    use rmcp::{ServerHandler, ServiceExt};

    #[derive(Clone)]
    struct HandoffTestServer;

    impl ServerHandler for HandoffTestServer {}

    fn caps_with_elicitation() -> ClientCapabilities {
        // The caller declares everything it can: elicitation, the tasks
        // extension, and the deprecated sampling/roots capabilities (set by
        // field to avoid the deprecated builder methods) — the mirror must
        // forward only elicitation.
        let mut caps = ClientCapabilities::builder()
            .enable_elicitation()
            .enable_tasks()
            .build();
        caps.sampling = Some(Default::default());
        caps.roots = Some(Default::default());
        caps
    }

    #[tokio::test]
    async fn disconnect_before_request_handoff_is_proven_pre_dispatch() {
        let (server_transport, client_transport) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let server = HandoffTestServer
                .serve(server_transport)
                .await
                .expect("server initializes");
            server.waiting().await.expect("server worker joins");
        });
        let info = ClientInfo::new(
            ClientCapabilities::default(),
            Implementation::new("handoff-test-client", "0.0.0"),
        );
        let mut client = info
            .serve(client_transport)
            .await
            .expect("client initializes");

        client.close().await.expect("client worker closes");
        assert!(client.peer().is_transport_closed());
        let error = call_tool_once_classified(
            &client,
            CallToolRequestParams::new("read"),
            Some(std::time::Duration::from_secs(1)),
        )
        .await
        .expect_err("a closed worker must reject the request before accepting a handle");

        assert_eq!(error.phase, ToolCallFailurePhase::PreDispatch);
        assert!(error.phase.dispatch_proven_absent());
        assert!(matches!(error.source, ServiceError::TransportClosed));
        server_task.await.expect("server task joins");
    }

    #[test]
    fn mirrors_elicitation_only_on_a_2026_lane() {
        let caps = caps_with_elicitation();
        let mirrored = mirrored_dial_capabilities(Some(&caps), Some("2026-07-28"))
            .expect("2026 lane with declared capabilities mirrors");
        assert!(mirrored.elicitation.is_some());
        // The tasks extension is the caller's contract with the gateway and
        // never crosses the upstream leg; sampling and roots have no
        // passthrough (deprecated in MCP 2026-07-28), so declaring them
        // must not invite upstream pauses the gateway would refuse.
        assert!(!mirrored.supports_tasks());
        assert!(mirrored.extensions.is_none());
        assert!(mirrored.experimental.is_none());
        assert!(mirrored.sampling.is_none());
        assert!(mirrored.roots.is_none());
    }

    #[test]
    fn no_mirror_for_legacy_lanes_or_absent_callers() {
        let caps = caps_with_elicitation();
        // Legacy-negotiated boot lane: never mirror, whatever the caller
        // declared — a legacy upstream never pauses, so there is no round
        // trip to protect.
        assert!(mirrored_dial_capabilities(Some(&caps), Some("2025-11-25")).is_none());
        // A caller that cannot receive pauses at all.
        assert!(mirrored_dial_capabilities(None, Some("2026-07-28")).is_none());
    }

    #[test]
    fn bare_2026_caller_gets_a_pinned_empty_declaration() {
        // A 2026 caller with no input-request capabilities can still
        // receive and echo a state-only pause, so its dial is pinned to
        // the 2026 generation with an empty declaration rather than
        // running an unpinned dial that could fall back to a legacy leg
        // mid-round-trip.
        let bare = ClientCapabilities::default();
        let mirrored = mirrored_dial_capabilities(Some(&bare), Some("2026-07-28"))
            .expect("pause-capable caller pins the dial");
        assert!(mirrored.elicitation.is_none());
        assert!(mirrored.sampling.is_none());
        assert!(mirrored.roots.is_none());
    }

    #[test]
    fn continuations_are_refused_where_2026_cannot_be_negotiated() {
        // `protocol: legacy` is the operator's escape hatch and SSE is
        // legacy by definition — neither can have issued a pause, and
        // caller-supplied retry fields must never force a lifecycle the
        // configuration disabled. `auto` (and explicit 2026) admit the
        // continuation, whose dial is then pinned.
        let auto: crate::UpstreamManifest =
            serde_yaml::from_str("name: mock\ntransport: http\nurl: http://127.0.0.1:1/mcp\n")
                .expect("manifest parses");
        assert!(manifest_continuation_refusal("mock", true, &auto).is_none());
        assert!(manifest_continuation_refusal("mock", false, &auto).is_none());

        let mut legacy = auto.clone();
        legacy.protocol = crate::UpstreamProtocol::Legacy;
        assert!(manifest_continuation_refusal("mock", true, &legacy).is_some());
        assert!(manifest_continuation_refusal("mock", false, &legacy).is_none());

        let sse: crate::UpstreamManifest =
            serde_yaml::from_str("name: mock\ntransport: sse\nurl: http://127.0.0.1:1/sse\n")
                .expect("sse manifest parses");
        assert!(manifest_continuation_refusal("mock", true, &sse).is_some());
    }

    #[test]
    fn pinned_manifest_requires_discovery() {
        let manifest: crate::UpstreamManifest =
            serde_yaml::from_str("name: mock\ntransport: http\nurl: http://127.0.0.1:1/mcp\n")
                .expect("minimal manifest parses");
        assert_eq!(
            pinned_2026_manifest(&manifest).protocol,
            crate::UpstreamProtocol::V20260728,
        );
    }
}
