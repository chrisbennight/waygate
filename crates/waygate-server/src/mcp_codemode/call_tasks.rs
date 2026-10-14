//! Background upstream tool calls for clients that declared the MCP tasks
//! extension, run on the Code Mode execution journal.
//!
//! A call task is one ordinary invocation: the same pipeline, governance,
//! inspection, validation, and file delivery a direct call gets. The journal
//! contributes what a background call needs and a direct call does not: an
//! owner-bound handle, a fenced worker claim renewed while the call is in
//! flight, cancellation, restart reconciliation, and bounded result
//! retention. Rows carry no source and no arguments; the stored result is the
//! call's exact `CallToolResult` (or the MCP error a direct caller would have
//! received), and is stored only because result storage is `allow`.

use rmcp::model::{DetailedTask, GetTaskResult, TaskPayload};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use waygate_codemode::TOOL_CALL_EXECUTION_PROFILE;
use waygate_invocation::{AdmittedDispatch, DispatchAdmission, InvocationError};
use waygate_mcp::call_tasks::{GatewayCallTasks, QualifiedCall};

use super::*;

/// Suggested polling interval for a background tool call.
const POLL_INTERVAL_MS: u64 = 1_000;
/// The single call a background tool-call execution makes is its first step.
const CALL_STEP: usize = 1;
/// Terminal reason of a call that ended with an MCP error.
const TOOL_CALL_FAILED: &str = "tool_call_failed";
/// Terminal reason and delivery error of a result too large to store.
const RESULT_TOO_LARGE: &str = "execution_result_too_large";

type TaskHandle = oneshot::Sender<Result<Task, InvocationError>>;
/// The submitting request's half of the start handshake. Whoever settles the
/// call first takes it: the admission with the task handle, or the worker
/// with the refusal that ended the call before admission.
type SharedTaskHandle = Arc<Mutex<Option<TaskHandle>>>;

/// What the admission tells the worker once the call is durably claimed.
struct Admitted {
    claim: ExecutionClaim,
    side_effects: bool,
}

impl CodeModeTools {
    /// Whether this deployment can run background tool calls: they need the
    /// durable journal and permission to store their results.
    pub(crate) fn call_tasks_available(&self) -> bool {
        self.durable_continuation_available()
    }
}

#[async_trait]
impl GatewayCallTasks for CodeModeTools {
    async fn start(
        &self,
        principal: &Principal,
        call: QualifiedCall,
    ) -> Result<Option<Task>, InvocationError> {
        // Declining here happens before any governance runs, so the caller
        // can still run the call synchronously without paying for it twice.
        // A caller that could not poll its own task gets the direct call.
        let Some(store) = self
            .execution_store
            .clone()
            .filter(|_| self.call_tasks_available() && may_invoke(principal))
        else {
            return Ok(None);
        };
        let Ok(detached) = self.acquire_detached_execution_slot() else {
            return Ok(None);
        };
        let Ok((tenant, global)) = self.execution_capacity.acquire_execution(principal) else {
            return Ok(None);
        };
        let execution_id = uuid::Uuid::now_v7();
        // Derived like a Code Mode connector call's identity, so the audit
        // trail and the journal name the call the same way.
        let call_id = uuid::Uuid::new_v5(&execution_id, &1u32.to_be_bytes());
        let hierarchy =
            InvocationHierarchy::new(execution_id, NonZeroU32::MIN, call_id, NonZeroU32::MIN);
        let cancellation = CancellationToken::new();
        let (handle_tx, handle_rx) = oneshot::channel();
        let handle: SharedTaskHandle = Arc::new(Mutex::new(Some(handle_tx)));
        let (admitted_tx, admitted_rx) = oneshot::channel();
        let admission = Arc::new(CallTaskAdmission {
            tools: self.clone(),
            store: store.clone(),
            principal: principal.clone(),
            execution_id,
            call_id,
            server: call.server.clone(),
            tool: call.tool.clone(),
            handle: handle.clone(),
            admitted: Mutex::new(Some(admitted_tx)),
        });
        // No caller capabilities: nobody is connected to answer an upstream
        // input request, so a pause fails closed instead of stranding the
        // call.
        let request = InvocationRequest::new(call.server.clone(), call.tool.clone())
            .with_arguments(call.arguments)
            .with_hierarchy(hierarchy)
            .with_cancellation(cancellation.clone())
            .with_dispatch_admission(admission);
        let worker = CallTaskWorker {
            tools: self.clone(),
            store,
            principal: principal.clone(),
            server: call.server,
            tool: call.tool,
            call_id,
            handle,
            cancellation,
        };
        self.execution_capacity
            .spawn_detached(hold_execution_permits_until(
                ExecutionPermits {
                    tenant,
                    detached: Some(detached),
                    global,
                },
                worker.run(request, admitted_rx),
            ));
        match handle_rx.await {
            Ok(Ok(task)) => Ok(Some(task)),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(InvocationError::Upstream(call_task_unavailable())),
        }
    }

    async fn get(
        &self,
        principal: &Principal,
        task_id: &str,
    ) -> Result<Option<GetTaskResult>, McpError> {
        let Some(record) = self
            .owned_status(
                principal,
                waygate_mcp::call_tasks::execution_id(task_id),
                OwnedProfile::ToolCall,
            )
            .await?
        else {
            return Ok(None);
        };
        let payload = match record.status {
            ExecutionStatus::Succeeded => {
                let Some(stored) = self.stored_payload(&record).await? else {
                    return Ok(None);
                };
                TaskPayload::Completed {
                    result: stored_object(stored)?,
                }
            }
            ExecutionStatus::Failed => {
                let error = match self.stored_payload(&record).await? {
                    Some(stored) => stored_object(stored)?,
                    None => unrecorded_failure(record.terminal_reason_code.as_deref()),
                };
                TaskPayload::Failed { error }
            }
            ExecutionStatus::Expired => TaskPayload::Failed {
                error: unrecorded_failure(record.terminal_reason_code.as_deref()),
            },
            ExecutionStatus::Cancelled => TaskPayload::Cancelled,
            _ => TaskPayload::Working,
        };
        let mut task = task_projection(&record);
        task.task_id = waygate_mcp::call_tasks::task_id(record.id);
        task.poll_interval_ms = Some(POLL_INTERVAL_MS);
        Ok(Some(GetTaskResult::new(DetailedTask::new(task, payload))))
    }

    async fn cancel(&self, principal: &Principal, task_id: &str) -> Result<bool, McpError> {
        let Some(record) = self
            .owned_status(
                principal,
                waygate_mcp::call_tasks::execution_id(task_id),
                OwnedProfile::ToolCall,
            )
            .await?
        else {
            return Ok(false);
        };
        let id = record.id;
        // A live worker observes the request through the cancellation watch
        // and cancels the upstream request; the call then ends `cancelled`.
        let requested = self
            .execution_store
            .as_ref()
            .ok_or_else(execution_unavailable)?
            .request_cancellation(
                principal.tenant.as_str(),
                &principal.sub,
                &principal.issuer,
                id,
            )
            .await
            .map_err(|error| {
                tracing::error!(%error, %id, "could not request background tool-call cancellation");
                execution_unavailable()
            })?;
        Ok(requested.is_some())
    }
}

impl CodeModeTools {
    /// The stored result payload of an owned terminal call. `None` when the
    /// row expired between the status read and this one.
    async fn stored_payload(
        &self,
        record: &ExecutionStatusRecord,
    ) -> Result<Option<Option<Value>>, McpError> {
        let execution = self
            .execution_store
            .as_ref()
            .ok_or_else(execution_unavailable)?
            .get(&record.tenant_id, record.id)
            .await
            .map_err(|error| {
                tracing::error!(%error, id = %record.id, "could not read background tool call");
                execution_unavailable()
            })?;
        Ok(execution.map(|execution| execution.result_payload))
    }
}

/// The execution profile of one background tool call. Ownership checks read
/// `profile_confinement`; reconciliation reads `resumable`, and a call is
/// never replayed after losing its worker.
fn tool_call_execution_profile(
    principal: &Principal,
    server: &str,
    tool: &str,
    side_effects: bool,
) -> Value {
    serde_json::json!({
        "name": TOOL_CALL_EXECUTION_PROFILE,
        "server": server,
        "tool": tool,
        "side_effects": side_effects,
        "profile_confinement": task_profile_confinement(principal),
        "resumable": false,
        "result_storage": "allow",
    })
}

/// Decode a stored result or error. Both are stored as their exact JSON text
/// so key order and every string survive the journal unchanged.
fn stored_object(stored: Option<Value>) -> Result<JsonObject, McpError> {
    match stored {
        Some(Value::String(text)) => serde_json::from_str(&text).map_err(|error| {
            tracing::error!(%error, "stored background tool-call result is unreadable");
            stored_result_unreadable()
        }),
        _ => Err(stored_result_unreadable()),
    }
}

fn stored_result_unreadable() -> McpError {
    McpError::internal_error(
        "The stored result of this background tool call is unavailable",
        Some(serde_json::json!({"error": "task_result_unavailable"})),
    )
}

/// The task error for a call that ended without a recorded result, such as
/// one whose worker was lost. `data.error` carries the journal's reason.
fn unrecorded_failure(reason: Option<&str>) -> JsonObject {
    let reason = reason.unwrap_or(TOOL_CALL_FAILED);
    let message = if reason == "effect_outcome_unknown" {
        "The gateway lost this background tool call after sending it; the effect may have \
         applied, so check the target system before repeating it"
    } else {
        "The background tool call ended without a recorded result"
    };
    error_object(&McpError::internal_error(
        message,
        Some(serde_json::json!({"error": reason})),
    ))
}

fn error_object(error: &McpError) -> JsonObject {
    match serde_json::to_value(error) {
        Ok(Value::Object(object)) => object,
        _ => JsonObject::new(),
    }
}

fn call_task_unavailable() -> McpError {
    McpError::internal_error(
        "Background tool-call storage is unavailable; the call was not sent upstream",
        Some(serde_json::json!({"error": "task_unavailable"})),
    )
}

fn call_task_abandoned() -> McpError {
    McpError::internal_error(
        "The request stopped waiting for its task handle; the call was not sent upstream",
        Some(serde_json::json!({"error": "task_abandoned"})),
    )
}

/// Durably admits one background call once the invocation pipeline has
/// passed every governance gate, and hands the submitting request its task
/// handle. A refusal here keeps the call from being dispatched.
struct CallTaskAdmission {
    tools: CodeModeTools,
    store: SharedExecutionStore,
    principal: Principal,
    execution_id: uuid::Uuid,
    call_id: uuid::Uuid,
    server: String,
    tool: String,
    handle: SharedTaskHandle,
    admitted: Mutex<Option<oneshot::Sender<Admitted>>>,
}

#[async_trait]
impl DispatchAdmission for CallTaskAdmission {
    async fn admit(&self, dispatch: AdmittedDispatch) -> Result<(), InvocationError> {
        let waiting = self
            .handle
            .lock()
            .expect("task handle lock poisoned")
            .as_ref()
            .is_some_and(|handle| !handle.is_closed());
        if !waiting {
            return Err(InvocationError::Upstream(call_task_abandoned()));
        }
        let id = self.execution_id;
        let tenant = self.principal.tenant.as_str();
        self.store
            .submit(NewExecution {
                id,
                tenant_id: tenant.to_owned(),
                principal_sub: self.principal.sub.clone(),
                principal_issuer: self.principal.issuer.clone(),
                source: None,
                source_digest: source_digest(""),
                program_input: None,
                execution_profile: tool_call_execution_profile(
                    &self.principal,
                    &self.server,
                    &self.tool,
                    dispatch.side_effects,
                ),
                sdk_contract_version: 0,
                runner_contract_version: 0,
                retention_until: time::OffsetDateTime::now_utc() + EXECUTION_RETENTION,
            })
            .await
            .map_err(|error| {
                tracing::error!(%error, %id, "could not submit background tool call");
                InvocationError::Upstream(call_task_unavailable())
            })?;
        let claimed = self
            .store
            .claim(
                tenant,
                id,
                uuid::Uuid::now_v7(),
                self.tools.claim_lease(),
                String::new(),
                serde_json::json!({
                    "server": self.server,
                    "tool": self.tool,
                    "contract": dispatch.contract,
                }),
            )
            .await;
        let (execution, claim) = match claimed {
            Ok(Some(claimed)) => claimed,
            outcome => {
                if let Err(error) = &outcome {
                    tracing::error!(%error, %id, "could not claim background tool call");
                }
                self.fail_unclaimed().await;
                return Err(InvocationError::Upstream(call_task_unavailable()));
            }
        };
        let detail = serde_json::json!({
            "server": self.server,
            "tool": self.tool,
            "side_effects": dispatch.side_effects,
        });
        // Journaled before dispatch, so a worker lost while a side-effecting
        // call is in flight reconciles as `effect_outcome_unknown`.
        if let Err(error) = self
            .tools
            .append_claimed_event(
                &claim,
                execution_event(
                    ExecutionEventKind::ConnectorCallStarted,
                    Some(CALL_STEP),
                    Some(self.call_id),
                    detail.clone(),
                ),
            )
            .await
        {
            self.fail_claimed(&claim, None).await;
            return Err(InvocationError::Upstream(error));
        }
        let mut task = task_projection(&ExecutionStatusRecord::from(&execution));
        task.task_id = waygate_mcp::call_tasks::task_id(id);
        task.poll_interval_ms = Some(POLL_INTERVAL_MS);
        let delivered = self
            .handle
            .lock()
            .expect("task handle lock poisoned")
            .take()
            .is_some_and(|handle| handle.send(Ok(task)).is_ok());
        if !delivered {
            // Nobody holds the handle, so nobody could poll or cancel the
            // call: end it here rather than dispatch it.
            self.fail_claimed(&claim, Some(detail)).await;
            return Err(InvocationError::Upstream(call_task_abandoned()));
        }
        if let Some(admitted) = self
            .admitted
            .lock()
            .expect("admission lock poisoned")
            .take()
        {
            // The worker drives this pipeline, so it is still receiving.
            let _ = admitted.send(Admitted {
                claim,
                side_effects: dispatch.side_effects,
            });
        }
        Ok(())
    }
}

impl CallTaskAdmission {
    /// End a submitted row that was never claimed.
    async fn fail_unclaimed(&self) {
        let id = self.execution_id;
        let failed = self
            .store
            .fail_submission(
                self.principal.tenant.as_str(),
                id,
                execution_event(
                    ExecutionEventKind::Failed,
                    None,
                    None,
                    serde_json::json!({"reason_code": "task_unavailable"}),
                ),
                "task_unavailable".to_owned(),
            )
            .await;
        if let Err(error) = failed {
            // Reconciliation ends an unclaimed submission once its grace
            // passes, so this row cannot stay pending forever.
            tracing::warn!(%error, %id, "could not end an unclaimed background tool call");
        }
    }

    /// End a claimed row whose call is not going to be dispatched. When the
    /// call-start event was journaled, `started` carries its detail so the
    /// journal records that call's outcome too.
    async fn fail_claimed(&self, claim: &ExecutionClaim, started: Option<Value>) {
        let (kind, step, call_id, detail) = match started {
            Some(detail) => (
                ExecutionEventKind::ConnectorCallFailed,
                Some(CALL_STEP),
                Some(self.call_id),
                detail,
            ),
            None => (
                ExecutionEventKind::Failed,
                None,
                None,
                serde_json::json!({"reason_code": "task_abandoned"}),
            ),
        };
        let failed = self
            .store
            .transition(
                claim,
                ExecutionTransition {
                    from: vec![ExecutionStatus::Running],
                    to: ExecutionStatus::Failed,
                    event: execution_event(kind, step, call_id, detail),
                    terminal_reason_code: Some("task_abandoned".to_owned()),
                    result_metadata: None,
                    result_payload: None,
                    resume_context: None,
                },
            )
            .await;
        match failed {
            Ok(Some(_)) => {}
            // Already terminal, for example cancelled by an operator.
            Ok(None) => {}
            Err(error) => tracing::warn!(
                %error,
                execution_id = %claim.execution_id,
                "could not end an undispatched background tool call"
            ),
        }
    }
}

/// Runs one admitted call to completion and journals its outcome.
struct CallTaskWorker {
    tools: CodeModeTools,
    store: SharedExecutionStore,
    principal: Principal,
    server: String,
    tool: String,
    call_id: uuid::Uuid,
    handle: SharedTaskHandle,
    cancellation: CancellationToken,
}

impl CallTaskWorker {
    async fn run(self, request: InvocationRequest, mut admitted: oneshot::Receiver<Admitted>) {
        let invoke = self.tools.invocation.invoke(Some(&self.principal), request);
        tokio::pin!(invoke);
        let admitted = tokio::select! {
            biased;
            admitted = &mut admitted => admitted.ok(),
            outcome = &mut invoke => {
                // The admission and a fast dispatch can settle in the same
                // poll; a sent claim means the call was admitted.
                match admitted.try_recv() {
                    Ok(admitted) => return self.record(&admitted, outcome).await,
                    Err(_) => return self.refuse(outcome),
                }
            }
        };
        let Some(admitted) = admitted else {
            // The admission was dropped without admitting: the pipeline
            // refused the call, or the admission did, before dispatch.
            let outcome = invoke.await;
            return self.refuse(outcome);
        };
        let execution_id = admitted.claim.execution_id;
        let _live = self
            .tools
            .execution_capacity
            .hold_claim(Some(&self.store), &admitted.claim, &self.principal)
            .await;
        let outcome = self
            .tools
            .await_effect_with_claim_renewal(Some(&admitted.claim), async {
                let mut check = self.tools.cancellation_check(execution_id);
                tokio::select! {
                    outcome = &mut invoke => outcome,
                    watched = self.tools.wait_for_cancellation(
                        &self.store,
                        &self.principal,
                        execution_id,
                        &mut check,
                    ) => {
                        // Cancel the upstream request, then keep waiting: an
                        // outcome already in flight still reaches the journal.
                        if watched.is_ok() {
                            self.cancellation.cancel();
                        }
                        (&mut invoke).await
                    }
                }
            })
            .await;
        self.record(&admitted, outcome).await;
    }

    /// Report a call that ended before admission to the submitting request.
    fn refuse(&self, outcome: Result<InvocationResponse, InvocationError>) {
        let error = match outcome {
            Err(error) => error,
            Ok(_) => {
                tracing::error!(
                    server = %self.server,
                    tool = %self.tool,
                    "the invocation service completed a background call without admitting it"
                );
                InvocationError::Upstream(McpError::internal_error(
                    "The call ran without being recorded as a task, so its result is \
                     unavailable; check the target system before repeating it",
                    Some(serde_json::json!({"error": "task_unavailable"})),
                ))
            }
        };
        if let Some(handle) = self
            .handle
            .lock()
            .expect("task handle lock poisoned")
            .take()
        {
            // A dropped receiver means the request was abandoned and nothing
            // was dispatched; there is nobody left to tell.
            let _ = handle.send(Err(error));
        }
    }

    /// Journal the terminal outcome of an admitted call.
    async fn record(
        &self,
        admitted: &Admitted,
        outcome: Result<InvocationResponse, InvocationError>,
    ) {
        let claim = &admitted.claim;
        let stored = match outcome {
            Ok(InvocationResponse::Unary(result)) => stored_result(&result, admitted.side_effects),
            Ok(_) => StoredOutcome::failed(
                &McpError::internal_error(
                    "the invocation service returned a response a tool call cannot carry",
                    None,
                ),
                TOOL_CALL_FAILED,
            ),
            Err(error) => StoredOutcome::failed(
                &waygate_mcp::server::tool_call_error(error, &self.server, &self.tool),
                TOOL_CALL_FAILED,
            ),
        };
        let event = execution_event(
            if stored.status == ExecutionStatus::Succeeded {
                ExecutionEventKind::ConnectorCallSucceeded
            } else {
                ExecutionEventKind::ConnectorCallFailed
            },
            Some(CALL_STEP),
            Some(self.call_id),
            serde_json::json!({
                "server": self.server,
                "tool": self.tool,
                "side_effects": admitted.side_effects,
            }),
        );
        let persisted = self
            .store
            .transition(
                claim,
                ExecutionTransition {
                    from: vec![ExecutionStatus::Running],
                    to: stored.status,
                    event: event.clone(),
                    terminal_reason_code: stored.reason_code,
                    result_metadata: stored.metadata,
                    result_payload: Some(Value::String(stored.payload)),
                    resume_context: None,
                },
            )
            .await;
        match persisted {
            Ok(Some(_)) => {}
            Ok(None) => {
                // A pending cancellation refuses the terminal write. The
                // call's outcome still belongs in the journal before the
                // cancellation finalizes the row.
                let _ = self.tools.append_claimed_effect_outcome(claim, event).await;
                match self
                    .tools
                    .finish_requested_cancellation(&self.store, claim)
                    .await
                {
                    Ok(true) | Err(_) => {}
                    Ok(false) => tracing::error!(
                        execution_id = %claim.execution_id,
                        "background tool call lost its claim before recording its outcome"
                    ),
                }
            }
            Err(error) => tracing::error!(
                %error,
                execution_id = %claim.execution_id,
                "could not record the outcome of a background tool call"
            ),
        }
    }
}

/// The terminal journal write for one call outcome.
struct StoredOutcome {
    status: ExecutionStatus,
    payload: String,
    reason_code: Option<String>,
    metadata: Option<Value>,
}

impl StoredOutcome {
    fn failed(error: &McpError, reason_code: &str) -> Self {
        Self {
            status: ExecutionStatus::Failed,
            payload: serde_json::to_string(error).unwrap_or_else(|_| "{}".to_owned()),
            reason_code: Some(reason_code.to_owned()),
            metadata: None,
        }
    }
}

/// Store a completed result exactly as a direct caller would have received
/// it, within the journal's result bound. Past the bound, a side-effecting
/// call keeps its succeeded outcome with an unavailable-delivery envelope, so
/// nobody repeats the effect to recover the result; a read fails instead.
fn stored_result(result: &CallToolResult, side_effects: bool) -> StoredOutcome {
    let is_error = result.is_error == Some(true);
    let succeeded = |payload: String| StoredOutcome {
        status: ExecutionStatus::Succeeded,
        payload,
        reason_code: None,
        metadata: Some(serde_json::json!({"is_error": is_error})),
    };
    let encoded = match serde_json::to_string(result) {
        Ok(encoded) => encoded,
        Err(error) => {
            tracing::error!(%error, "could not encode a background tool-call result");
            return StoredOutcome::failed(
                &McpError::internal_error("the tool result could not be encoded", None),
                TOOL_CALL_FAILED,
            );
        }
    };
    if encoded.len() <= limits().result_bytes {
        return succeeded(encoded);
    }
    if side_effects && !is_error {
        let envelope = waygate_mcp::retained_delivery::delivery_failure(
            CallToolResult::success(Vec::new()),
            RESULT_TOO_LARGE,
        );
        if let Ok(encoded) = serde_json::to_string(&envelope) {
            return succeeded(encoded);
        }
    }
    StoredOutcome::failed(&result_too_large(), RESULT_TOO_LARGE)
}

fn result_too_large() -> McpError {
    McpError::internal_error(
        "The tool result exceeds the size a task can store",
        Some(serde_json::json!({
            "error": RESULT_TOO_LARGE,
            "limit_bytes": limits().result_bytes,
        })),
    )
}
