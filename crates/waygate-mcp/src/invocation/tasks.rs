//! Governed lifecycle access for upstream-owned Tasks.
use super::*;
use crate::tasks::{TaskRoute, TaskRpc, TaskSealer};
use rmcp::model::{ClientCapabilities, CreateTaskResult, TaskPayload};
use serde_json::{Map, Value};
use waygate_invocation::{TaskAction, TaskResponse};

impl DefaultInvocationService {
    #[must_use]
    pub fn with_task_sealer(mut self, sealer: Option<Arc<TaskSealer>>) -> Self {
        self.task_sealer = sealer;
        self
    }

    pub(super) async fn prepare_task_origin(
        &self,
        ctx: &mut InvocationContext<'_>,
    ) -> Result<(), InvocationError> {
        let requested = ctx
            .mrtr
            .caller_capabilities
            .as_ref()
            .is_some_and(|c| c.supports_tasks());
        if !requested {
            return Ok(());
        }
        let binding = if self.task_sealer.is_some() && ctx.principal.is_some() {
            self.catalog.task_binding(ctx.server).await
        } else {
            None
        };
        let Some(binding) = binding else {
            if let Some(extensions) = ctx
                .mrtr
                .caller_capabilities
                .as_mut()
                .and_then(|c| c.extensions.as_mut())
            {
                extensions.remove(rmcp::model::TASKS_EXTENSION_ID);
            }
            return Ok(());
        };
        let mut operation_arguments = Map::new();
        if let Some(key) = ctx.tool_snapshot().discriminator() {
            if let Some(value) = ctx.arguments.as_ref().and_then(|a| a.get(key)) {
                operation_arguments.insert(key.to_owned(), value.clone());
            }
        }
        ctx.task_origin = Some(TaskRoute::new(
            ctx.principal.expect("authenticated task admission"),
            ctx.server,
            ctx.tool,
            binding.clone(),
            ctx.tool_snapshot().contract_identity(),
            operation_arguments,
            ctx.pip_facts()
                .request
                .clone()
                .expect("admitted request facts"),
        ));
        ctx.mrtr.task_binding = Some(binding);
        Ok(())
    }

    pub(super) async fn admit_upstream_task(
        &self,
        ctx: &mut InvocationContext<'_>,
        task: &mut CreateTaskResult,
    ) -> Result<CallToolResult, InvocationError> {
        let route = ctx.task_origin.take().ok_or_else(|| {
            InvocationError::Upstream(ErrorData::internal_error(
                "upstream returned a task envelope without negotiated gateway task support",
                None,
            ))
        })?;
        self.inspect_task_metadata(
            ctx,
            serde_json::to_value(&*task).map_err(|_| invalid("invalid upstream task"))?,
            task.meta.clone(),
        )
        .await?;
        self.task_sealer
            .as_ref()
            .expect("task admission requires a sealer")
            .seal(route, &mut task.task)
            .map_err(InvocationError::Upstream)?;
        Ok(CallToolResult::success(vec![]))
    }

    async fn inspect_task_metadata(
        &self,
        ctx: &mut InvocationContext<'_>,
        value: Value,
        meta: Option<rmcp::model::MetaObject>,
    ) -> Result<(), InvocationError> {
        let mut original = CallToolResult::structured(value);
        original.meta = meta;
        let inspected = self.inspect_response(ctx, Ok(original.clone())).await?;
        if inspected != original {
            return Err(invalid(
                "task metadata cannot be redacted safely; response withheld",
            ));
        }
        Ok(())
    }

    pub(super) async fn upstream_task(
        &self,
        principal: Option<&Principal>,
        handle: &str,
        action: TaskAction,
        capabilities: ClientCapabilities,
    ) -> Result<TaskResponse, InvocationError> {
        let principal =
            principal.ok_or_else(|| InvocationError::Upstream(crate::tasks::not_found()))?;
        let sealer = self
            .task_sealer
            .as_ref()
            .ok_or_else(|| InvocationError::Upstream(crate::tasks::not_found()))?;
        let route = sealer
            .open(handle, principal)
            .map_err(InvocationError::Upstream)?;
        if !capabilities.supports_tasks() {
            return Err(invalid(
                "declare io.modelcontextprotocol/tasks on each lifecycle request",
            ));
        }
        let mut ctx = InvocationContext {
            principal: Some(principal),
            task_origin: None,
            task_action: Some(match &action {
                TaskAction::Get => "TaskGet",
                TaskAction::Update(_) => "TaskUpdate",
                TaskAction::Cancel => "TaskCancel",
            }),
            server: &route.server,
            tool: &route.tool,
            invocation_id: uuid::Uuid::new_v4(),
            tool_snapshot: None,
            effective_facts: None,
            operation: None,
            operation_classified: false,
            pip_facts: None,
            arguments: Some(route.operation_arguments.clone()),
            mrtr: crate::catalog::ToolCallMrtr::default(),
            latency_ms: None,
            authz_policy_ids: vec![],
            pending_redactions: vec![],
            audit_category: EvidenceCategory::Invocation,
            responses_surface: false,
            embeddings_surface: false,
            images_surface: None,
            acting_agent: None,
            invocation_hierarchy: None,
            approval_binding: None,
            channel: waygate_invocation::InvocationChannel::Direct,
            response_materialization_limit_bytes: None,
            response_delivery: waygate_invocation::ResponseDelivery::File,
            retained_response: std::sync::Mutex::new(None),
            retained_operation_succeeded: std::sync::atomic::AtomicBool::new(false),
            cedar_approval_policies: None,
            policy_gated_grant_consumed: false,
            continuation: continuation::CallState::default(),
            compiled_input_validator: None,
        };
        self.resolve_tool(&mut ctx).await?;
        // Re-evaluate the current policy, but never transfer an old task to a different contract.
        if ctx.tool_snapshot().contract_identity() != route.contract {
            return Err(invalid("task's originating tool contract changed; restore the original configuration to access it"));
        }
        self.extract_facts(&mut ctx).await?;
        // Only the immutable request projection comes from the handle. Identity,
        // classification, policy, and ambient context are evaluated afresh.
        ctx.pip_facts
            .as_mut()
            .expect("authenticated task facts")
            .request = Some(route.request_facts.clone());
        self.authorize(&mut ctx).await?;
        self.check_profile_restrictions(&mut ctx).await?;
        self.prepare_output_validation(&mut ctx).await?;
        // Reading status and requesting cancellation consume no new execution approval.
        // Input advances work and is governed by the original operation's current policy.
        if let TaskAction::Update(responses) = &action {
            ctx.arguments = Some(Map::from_iter([
                ("taskId".to_owned(), Value::String(handle.to_owned())),
                (
                    "inputResponses".to_owned(),
                    serde_json::to_value(responses).map_err(|_| invalid("invalid task input"))?,
                ),
            ]));
            // Unknown/stale keys are handled atomically by the upstream. File values are
            // refused here until an outstanding elicitation has authorized their delivery.
            if let Some(processor) = &self.file_input_processor {
                processor
                    .admit(None, None, &mut None, Some(responses), &[])
                    .map_err(InvocationError::Upstream)?;
            }
        }
        self.check_quota(&mut ctx).await?;
        if matches!(&action, TaskAction::Update(_)) {
            self.check_approval(&mut ctx).await?;
        }
        self.record_pre_call(&mut ctx).await?;
        let processor = retained_response::RetainedResponseProcessor::new(self, &ctx);
        let result = self
            .catalog
            .task_request(
                &route.server,
                &route.tool,
                principal,
                &route.contract,
                TaskRpc {
                    task_id: route.upstream_id.clone(),
                    action,
                    binding: route.binding.clone(),
                    capabilities,
                    expires_at: route.exp,
                    created_at: route.created_at.clone(),
                },
                &processor,
            )
            .await;
        let mut response = match result {
            Ok(response) => response,
            Err(error) => {
                let error = Err(error);
                self.record_outcome(&mut ctx, &error).await;
                return error.map(|_| unreachable!("recorded error outcome"));
            }
        };
        if let TaskResponse::Status(status) = &mut response {
            if status.task.task.task_id != route.upstream_id
                || status.task.task.created_at != route.created_at
            {
                return Err(invalid("upstream returned a different task identity"));
            }
            let metadata = if matches!(status.task.payload, TaskPayload::Completed { .. }) {
                serde_json::to_value(&status.task.task)
            } else {
                serde_json::to_value(&*status)
            }
            .map_err(|_| invalid("invalid task metadata"))?;
            self.inspect_task_metadata(&mut ctx, metadata, status.meta.clone())
                .await?;
            if let TaskPayload::Completed { result } = &mut status.task.payload {
                let completed: CallToolResult =
                    serde_json::from_value(Value::Object(result.clone())).map_err(|_| {
                        invalid("upstream terminal task result is not a tool result")
                    })?;
                let completed = self.inspect_response(&mut ctx, Ok(completed)).await;
                let completed = self
                    .prepare_files_and_validate_output(&mut ctx, completed)
                    .await?;
                self.record_outcome(&mut ctx, &completed).await;
                let completed = completed?;
                *result = serde_json::to_value(completed)
                    .map_err(|_| invalid("could not encode task result"))?
                    .as_object()
                    .cloned()
                    .ok_or_else(|| invalid("invalid task result"))?;
            } else {
                self.record_outcome(&mut ctx, &Ok(CallToolResult::success(vec![])))
                    .await;
            }
            // Preserve the stable client handle; polling never extends its lifetime.
            status.task.task.task_id = handle.to_owned();
            status.task.task.ttl_ms = Some(
                status
                    .task
                    .task
                    .ttl_ms
                    .unwrap_or(u64::MAX)
                    .min(route.ttl_ms),
            );
            self.flush_pending_redactions(&mut ctx).await;
        } else {
            self.record_outcome(&mut ctx, &Ok(CallToolResult::success(vec![])))
                .await;
        }
        Ok(response)
    }
}
fn invalid(message: &'static str) -> InvocationError {
    InvocationError::Upstream(crate::tasks::invalid(message))
}
