//! Task RPCs use the same checked-out connection, identity, and contract gates
//! as the tool that created them. No lifecycle state or worker lives here.
use super::*;
use rmcp::model::{
    CancelTaskParams, CancelTaskRequest, ClientCapabilities, ClientRequest, GetTaskParams,
    GetTaskRequest, ServerResult, UpdateTaskParams, UpdateTaskRequest,
};
use waygate_invocation::{TaskAction, TaskResponse};
use waygate_mcp::catalog::{CallToolResultProcessor, InvocationError};
use waygate_mcp::tasks::TaskRpc;

pub(super) fn binding(manifest: &UpstreamManifest) -> Option<String> {
    // Whole-manifest binding intentionally invalidates handles after configuration
    // changes. Restoring the exact configuration makes retained handles usable again.
    serde_json::to_value(manifest)
        .ok()
        .map(|value| waygate_catalog::validator_schema_hash(&value))
}

pub(super) enum DispatchResponse {
    Tool(Box<CallToolResponse>),
    Task(TaskResponse),
}

pub(super) fn request(rpc: &TaskRpc) -> ClientRequest {
    match &rpc.action {
        TaskAction::Get => {
            ClientRequest::GetTaskRequest(GetTaskRequest::new(GetTaskParams::new(&rpc.task_id)))
        }
        TaskAction::Cancel => ClientRequest::CancelTaskRequest(CancelTaskRequest::new(
            CancelTaskParams::new(&rpc.task_id),
        )),
        TaskAction::Update(input) => ClientRequest::UpdateTaskRequest(UpdateTaskRequest::new(
            UpdateTaskParams::new(&rpc.task_id, input.clone()),
        )),
    }
}

pub(super) async fn dispatch_once(
    service: &RunningService<RoleClient, ClientInfo>,
    params: rmcp::model::CallToolRequestParams,
    task: Option<&TaskRpc>,
    capabilities: Option<&ClientCapabilities>,
    file_output: bool,
    cleartext_control_plane: bool,
    timeout: Option<Duration>,
) -> Result<DispatchResponse, dispatch::ToolCallAttemptError> {
    let mirrored = task
        .map(|task| &task.capabilities)
        .or(capabilities)
        .map(task_capabilities);
    let meta = if file_output {
        Some(file_transfers::client_capability_meta(
            mirrored.as_ref().unwrap_or(&service.service().capabilities),
            waygate_mcp::files::FileOperation::Download,
            cleartext_control_plane,
        ))
    } else {
        mirrored.map(|caps| {
            let mut meta = rmcp::model::RequestMetaObject::default();
            meta.insert(
                waygate_mcp::files::CLIENT_CAPABILITIES_META_KEY.to_owned(),
                serde_json::to_value(caps).expect("capabilities serialize"),
            );
            meta
        })
    };
    let Some(task) = task else {
        return dispatch::call_tool_once_with_meta(service, params, meta, timeout)
            .await
            .map(|result| DispatchResponse::Tool(Box::new(result)));
    };
    if task.expires_at <= time::OffsetDateTime::now_utc().unix_timestamp() {
        return Err(dispatch::ToolCallAttemptError {
            phase: dispatch::ToolCallFailurePhase::PreDispatch,
            source: rmcp::service::ServiceError::McpError(McpError::invalid_params(
                "task expired",
                None,
            )),
            retryable: false,
        });
    }
    let request = request(task);
    let result = dispatch::send_once_classified(service, request, meta, timeout).await?;
    let response = match (&task.action, result) {
        (TaskAction::Get, ServerResult::GetTaskResult(result))
            if result.task.task.task_id == task.task_id
                && result.task.task.created_at == task.created_at =>
        {
            TaskResponse::Status(Box::new(result))
        }
        (TaskAction::Update(_) | TaskAction::Cancel, ServerResult::TaskAckResult(_)) => {
            TaskResponse::Acknowledged
        }
        _ => {
            return Err(dispatch::ToolCallAttemptError {
                phase: dispatch::ToolCallFailurePhase::DispatchedUnknownOutcome,
                source: rmcp::service::ServiceError::UnexpectedResponse,
                retryable: false,
            })
        }
    };
    Ok(DispatchResponse::Task(response))
}

impl UpstreamPool {
    pub(super) async fn task_binding_inner(&self, server: &str) -> Option<String> {
        let entry = self.entries.load().get(server).cloned()?;
        if entry.removed.load(Ordering::Acquire) {
            return None;
        }
        let manifest = entry.manifest_snapshot();
        for slot in &entry.slots {
            let guard = slot.conn.read().await;
            if let Some(conn) = guard.as_ref() {
                if conn.negotiated_protocol.as_deref() == Some("2026-07-28")
                    && conn
                        .client
                        .peer_info()
                        .is_some_and(|info| info.capabilities.supports_tasks())
                {
                    return binding(&manifest);
                }
            }
        }
        None
    }

    pub(super) async fn task_request_inner(
        &self,
        server: &str,
        tool: &str,
        principal: &Principal,
        admitted: &InvocationContractIdentity,
        request: TaskRpc,
        processor: &dyn CallToolResultProcessor,
    ) -> Result<TaskResponse, InvocationError> {
        let _routing_guard = self.resource_routing.read().await;
        let mrtr = ToolCallMrtr {
            caller_capabilities: Some(request.capabilities.clone()),
            task_binding: Some(request.binding.clone()),
            ..Default::default()
        };
        let result = self
            .call_tool_inner(
                server,
                tool,
                None,
                Some(principal),
                Some(admitted),
                dispatch::ToolCallDispatchOptions {
                    mrtr,
                    processor: Some(processor),
                    task: Some(request),
                },
            )
            .await
            .map_err(InvocationError::Upstream)?;
        match result {
            dispatch::ProcessedCallToolResponse::Task(response) => Ok(response),
            dispatch::ProcessedCallToolResponse::ProcessingError(error) => Err(error.into_error()),
            _ => Err(InvocationError::Upstream(McpError::internal_error(
                "unexpected task response",
                None,
            ))),
        }
    }
}

fn task_capabilities(caller: &ClientCapabilities) -> ClientCapabilities {
    let mut result = ClientCapabilities::default();
    result.elicitation = caller.elicitation.clone();
    result.extensions = caller.extensions.as_ref().map(|extensions| {
        extensions
            .iter()
            .filter(|(name, _)| name.as_str() == rmcp::model::TASKS_EXTENSION_ID)
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect()
    });
    result
}
