//! Conservative recovery for per-call HTTP upstream setup and request handoff.

use rmcp::model::{CallToolRequestParams, ClientCapabilities, ClientInfo};
use rmcp::service::RunningService;
use rmcp::{ErrorData as McpError, RoleClient};

use waygate_mcp::catalog::{CallToolResultProcessor, InvocationContractIdentity};
use waygate_oidc::SharedIdentityIssuer;

use crate::identity_client::{IdentityCell, IdentityContext};
use crate::transport::DialError;
use crate::UpstreamManifest;

use super::dispatch::{ProcessedCallToolResponse, ToolCallAttemptError, ToolCallFailurePhase};
use super::{
    admission, dispatch, resources, ExchangeBundle, UpstreamEntry, UpstreamErrorClass, UpstreamPool,
};

struct PerCallDial<'a> {
    snapshot: &'a UpstreamManifest,
    forwards_identity: bool,
    issuer: Option<&'a SharedIdentityIssuer>,
    exchange: Option<&'a ExchangeBundle>,
    prebuilt_context: Option<&'a IdentityContext>,
    caller_capabilities: Option<&'a ClientCapabilities>,
    negotiated_protocol: Option<&'a str>,
    has_continuation: bool,
    deadline: Option<tokio::time::Instant>,
    timeout: Option<std::time::Duration>,
    server: &'a str,
    tool_name: &'a str,
    trace_id: &'a str,
    safe_retry: bool,
    attempts: usize,
}

struct PerCallDialSuccess {
    service: RunningService<RoleClient, ClientInfo>,
    attempts: usize,
}

struct PerCallDialFailure {
    error: DialError,
    phase: ToolCallFailurePhase,
    attempts: usize,
    retryable: bool,
}

pub(super) struct PerCallExecution<'a> {
    pub(super) pool: &'a UpstreamPool,
    pub(super) snapshot: &'a UpstreamManifest,
    pub(super) current_manifest: &'a UpstreamManifest,
    pub(super) entry: &'a UpstreamEntry,
    pub(super) issuer: Option<&'a SharedIdentityIssuer>,
    pub(super) exchange: Option<&'a ExchangeBundle>,
    pub(super) prebuilt_context: Option<&'a IdentityContext>,
    pub(super) caller_capabilities: Option<&'a ClientCapabilities>,
    pub(super) negotiated_protocol: Option<&'a str>,
    pub(super) admitted: Option<&'a InvocationContractIdentity>,
    pub(super) has_continuation: bool,
    pub(super) approval_gated: bool,
    pub(super) deadline: Option<tokio::time::Instant>,
    pub(super) timeout: Option<std::time::Duration>,
    pub(super) server: &'a str,
    pub(super) tool_name: &'a str,
    pub(super) advertised_tool: Option<&'a rmcp::model::Tool>,
    pub(super) trace_id: &'a str,
    pub(super) params: CallToolRequestParams,
    pub(super) processor: Option<&'a dyn CallToolResultProcessor>,
}

pub(super) enum PerCallExecutionOutcome {
    Finished {
        result: Result<ProcessedCallToolResponse, ToolCallAttemptError>,
        attempts: usize,
    },
    Failed {
        error: McpError,
        error_class: UpstreamErrorClass,
    },
}

pub(super) fn remaining(deadline: Option<tokio::time::Instant>) -> Option<std::time::Duration> {
    deadline.map(|deadline| {
        deadline
            .checked_duration_since(tokio::time::Instant::now())
            .unwrap_or_default()
    })
}

fn deadline_is_live(deadline: Option<tokio::time::Instant>) -> bool {
    deadline.is_none_or(|deadline| deadline > tokio::time::Instant::now())
}

fn handoff_budget(
    deadline: Option<tokio::time::Instant>,
    timeout: Option<std::time::Duration>,
) -> Result<Option<std::time::Duration>, ToolCallAttemptError> {
    match remaining(deadline) {
        Some(budget) if budget.is_zero() => Err(ToolCallAttemptError {
            phase: ToolCallFailurePhase::PreDispatch,
            source: rmcp::service::ServiceError::Timeout {
                timeout: timeout.unwrap_or_default(),
            },
            retryable: false,
        }),
        budget => Ok(budget),
    }
}

fn can_retry(
    safe_retry: bool,
    attempts: usize,
    phase: ToolCallFailurePhase,
    deadline: Option<tokio::time::Instant>,
) -> bool {
    safe_retry && attempts == 1 && phase.dispatch_proven_absent() && deadline_is_live(deadline)
}

async fn close_service(
    service: RunningService<RoleClient, ClientInfo>,
    deadline: Option<tokio::time::Instant>,
) {
    match remaining(deadline) {
        Some(remaining) if remaining.is_zero() => drop(service),
        Some(remaining) => {
            let _ = tokio::time::timeout(remaining, service.cancel()).await;
        }
        None => {
            let _ = service.cancel().await;
        }
    }
}

/// Execute one per-call session through the complete pre-dispatch lifecycle.
/// A second attempt is admitted only when the exact tool contract is safe and
/// the failed phase proves that the tool request never entered the transport.
pub(super) async fn execute_per_call(setup: PerCallExecution<'_>) -> PerCallExecutionOutcome {
    let retry_permitted_by_policy = setup
        .snapshot
        .session
        .as_ref()
        .is_none_or(crate::SessionConfig::retries_safe_setup_failures);
    let safe_retry = matches!(setup.snapshot.transport, crate::Transport::Http)
        && retry_permitted_by_policy
        && dispatch::admitted_safe_retry(
            setup.admitted,
            setup.has_continuation,
            setup.approval_gated,
        );
    let mut attempts = 1_usize;
    loop {
        let dial = dial_per_call(PerCallDial {
            snapshot: setup.snapshot,
            forwards_identity: setup.entry.forwards_identity,
            issuer: setup.issuer,
            exchange: setup.exchange,
            prebuilt_context: setup.prebuilt_context,
            caller_capabilities: setup.caller_capabilities,
            negotiated_protocol: setup.negotiated_protocol,
            has_continuation: setup.has_continuation,
            deadline: setup.deadline,
            timeout: setup.timeout,
            server: setup.server,
            tool_name: setup.tool_name,
            trace_id: setup.trace_id,
            safe_retry,
            attempts,
        })
        .await;
        let service = match dial {
            Ok(success) => {
                attempts = success.attempts;
                success.service
            }
            Err(failure) => {
                return PerCallExecutionOutcome::Failed {
                    error: bounded_dial_error(setup.server, &failure, setup.trace_id),
                    error_class: UpstreamErrorClass::from_dial_error(&failure.error),
                };
            }
        };

        if matches!(
            setup.current_manifest.classification_mode,
            crate::ClassificationMode::McpAnnotations
        ) {
            let session_tools = setup
                .pool
                .session_tools_bounded(&service, remaining(setup.deadline))
                .await;
            match session_tools {
                Ok(tools)
                    if setup
                        .pool
                        .observe_tool_reviews(
                            setup.entry,
                            setup.server,
                            setup.current_manifest,
                            tools
                                .iter()
                                .find(|tool| tool.name.as_ref() == setup.tool_name)
                                .map(std::slice::from_ref)
                                .unwrap_or_default(),
                        )
                        .await
                        .is_ok()
                        && setup
                            .pool
                            .review_allows(
                                setup.server,
                                setup.tool_name,
                                tools
                                    .iter()
                                    .find(|tool| tool.name.as_ref() == setup.tool_name),
                                setup.current_manifest.classification_mode,
                            )
                            .await
                        && admission::tool_is_admitted_in_catalog(
                            setup.current_manifest,
                            &tools,
                            setup.tool_name,
                        ) => {}
                Ok(_) => {
                    if attempts > 1 {
                        dispatch::record_retry_exhausted(setup.server);
                    }
                    waygate_telemetry::metrics::record_tool_drift(setup.server);
                    tracing::warn!(
                        server = setup.server,
                        tool_name = setup.tool_name,
                        "per-call session advertises a contract that does not match the approved behavior hash; refusing dispatch",
                    );
                    close_service(service, setup.deadline).await;
                    return PerCallExecutionOutcome::Failed {
                        error: McpError::internal_error(
                            format!(
                                "upstream `{}` per-call session advertises a different contract for `{}` than the approved behavior",
                                setup.server, setup.tool_name,
                            ),
                            None,
                        ),
                        error_class: UpstreamErrorClass::Protocol,
                    };
                }
                Err(error) => {
                    let phase = ToolCallFailurePhase::PreDispatch;
                    let retry = can_retry(safe_retry, attempts, phase, setup.deadline);
                    tracing::warn!(
                        server = setup.server,
                        tool_name = setup.tool_name,
                        trace_id = setup.trace_id,
                        attempt = attempts,
                        phase = phase.as_str(),
                        error = %error,
                        will_retry = retry,
                        "per-call session contract read failed",
                    );
                    dispatch::record_failure(setup.server, phase);
                    let error_class = error.error_class();
                    if retry {
                        close_service(service, setup.deadline).await;
                        dispatch::record_retry_attempt(setup.server);
                        attempts += 1;
                        continue;
                    }
                    close_service(service, setup.deadline).await;
                    if attempts > 1 {
                        dispatch::record_retry_exhausted(setup.server);
                    }
                    return PerCallExecutionOutcome::Failed {
                        error: dispatch::bounded_upstream_error(
                            setup.server,
                            phase,
                            safe_retry,
                            attempts,
                            setup.trace_id,
                        ),
                        error_class,
                    };
                }
            }
        }

        if !setup
            .pool
            .review_allows(
                setup.server,
                setup.tool_name,
                setup.advertised_tool,
                setup.current_manifest.classification_mode,
            )
            .await
        {
            close_service(service, setup.deadline).await;
            return PerCallExecutionOutcome::Failed {
                error: admission::contract_changed_error(setup.server, setup.tool_name),
                error_class: UpstreamErrorClass::Protocol,
            };
        }

        let mut response = match handoff_budget(setup.deadline, setup.timeout) {
            Ok(budget) => {
                dispatch::call_tool_once_classified(&service, setup.params.clone(), budget).await
            }
            Err(error) => Err(error),
        };
        if let Err(error) = response.as_mut() {
            let retry = can_retry(safe_retry, attempts, error.phase, setup.deadline);
            if retry {
                tracing::warn!(
                    server = setup.server,
                    tool_name = setup.tool_name,
                    trace_id = setup.trace_id,
                    attempt = attempts,
                    phase = error.phase.as_str(),
                    error = %error.source,
                    "upstream request handoff failed before dispatch; retrying safe call",
                );
                dispatch::record_failure(setup.server, error.phase);
                dispatch::record_retry_attempt(setup.server);
                attempts += 1;
                close_service(service, setup.deadline).await;
                continue;
            }
            error.retryable = safe_retry
                && error.phase.dispatch_proven_absent()
                && deadline_is_live(setup.deadline);
        }
        let reader = resources::SessionResourceReader {
            server: setup.server,
            client: &service,
            timeout: remaining(setup.deadline),
            bounded_reads_supported: matches!(setup.snapshot.transport, crate::Transport::Http),
        };
        let result = dispatch::process_call_response(response, setup.processor, &reader).await;
        close_service(service, setup.deadline).await;
        return PerCallExecutionOutcome::Finished { result, attempts };
    }
}

/// Dial a per-call session. A dial failure may consume the one shared recovery
/// attempt; callers pass the current attempt count so later phases cannot reset
/// the budget.
async fn dial_per_call(setup: PerCallDial<'_>) -> Result<PerCallDialSuccess, PerCallDialFailure> {
    let mut attempts = setup.attempts;
    loop {
        let cell = setup.forwards_identity.then(IdentityCell::new);
        if let (Some(cell), Some(context)) = (cell.as_ref(), setup.prebuilt_context) {
            cell.set(context.clone());
        }
        let dial = dispatch::per_call_dial(
            setup.snapshot,
            setup.issuer,
            cell.as_ref(),
            setup.exchange,
            setup.caller_capabilities,
            setup.negotiated_protocol,
            setup.has_continuation,
        );
        let dial_result = match remaining(setup.deadline) {
            Some(remaining) => match tokio::time::timeout(remaining, dial).await {
                Ok(result) => result,
                Err(_) => Err(DialError::HandshakeTimeout(
                    setup.timeout.unwrap_or_default(),
                )),
            },
            None => dial.await,
        };
        match dial_result {
            Ok(service) => return Ok(PerCallDialSuccess { service, attempts }),
            Err(error) => {
                let phase = ToolCallFailurePhase::from_dial_error(&error);
                dispatch::record_failure(setup.server, phase);
                let retry = can_retry(setup.safe_retry, attempts, phase, setup.deadline);
                tracing::warn!(
                    server = setup.server,
                    tool_name = setup.tool_name,
                    trace_id = setup.trace_id,
                    attempt = attempts,
                    phase = phase.as_str(),
                    error = %error,
                    will_retry = retry,
                    "per-call upstream setup failed",
                );
                if retry {
                    dispatch::record_retry_attempt(setup.server);
                    attempts += 1;
                    continue;
                }
                if attempts > 1 {
                    dispatch::record_retry_exhausted(setup.server);
                }
                return Err(PerCallDialFailure {
                    error,
                    phase,
                    attempts,
                    retryable: phase.dispatch_proven_absent()
                        && setup.safe_retry
                        && deadline_is_live(setup.deadline),
                });
            }
        }
    }
}

fn bounded_dial_error(server: &str, failure: &PerCallDialFailure, trace_id: &str) -> McpError {
    dispatch::bounded_upstream_error(
        server,
        failure.phase,
        failure.retryable,
        failure.attempts,
        trace_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn admitted_safe_call_bounds_a_dial_failure_to_one_recovery_attempt() {
        let manifest: UpstreamManifest =
            serde_yaml::from_str("name: provider-neutral\ntransport: http\nprotocol: legacy\n")
                .expect("manifest fixture parses");

        let failure = match dial_per_call(PerCallDial {
            snapshot: &manifest,
            forwards_identity: false,
            issuer: None,
            exchange: None,
            prebuilt_context: None,
            caller_capabilities: None,
            negotiated_protocol: None,
            has_continuation: false,
            deadline: None,
            timeout: None,
            server: "provider-neutral",
            tool_name: "read",
            trace_id: "trace-dial-failure",
            safe_retry: true,
            attempts: 1,
        })
        .await
        {
            Ok(_) => panic!("a missing HTTP URL must fail before initialization"),
            Err(failure) => failure,
        };

        assert!(matches!(failure.error, DialError::MissingUrl));
        assert_eq!(failure.phase, ToolCallFailurePhase::Dial);
        assert_eq!(failure.attempts, 2, "the dial gets one recovery attempt");
        assert!(failure.retryable, "dispatch is proven absent at dial time");
    }

    #[test]
    fn request_handoff_failure_uses_the_same_single_attempt_budget() {
        assert!(can_retry(true, 1, ToolCallFailurePhase::PreDispatch, None));
        assert!(!can_retry(true, 2, ToolCallFailurePhase::PreDispatch, None));
    }

    #[test]
    fn expired_deadline_refuses_handoff_before_a_send_future_is_built() {
        let deadline = tokio::time::Instant::now() - std::time::Duration::from_millis(1);
        let configured_timeout = std::time::Duration::from_secs(7);

        let error = handoff_budget(Some(deadline), Some(configured_timeout))
            .expect_err("an expired deadline must stop before request handoff");

        assert_eq!(error.phase, ToolCallFailurePhase::PreDispatch);
        assert!(!error.retryable);
        assert!(matches!(
            error.source,
            rmcp::service::ServiceError::Timeout { timeout } if timeout == configured_timeout
        ));
    }
}
