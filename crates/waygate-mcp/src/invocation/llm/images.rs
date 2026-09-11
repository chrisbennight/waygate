//! Images use the same model admission and policy gates as other inference calls.

use super::*;

impl DefaultInvocationService {
    pub(in crate::invocation) async fn invoke_images(
        &self,
        mut ctx: InvocationContext<'_>,
        model: ResolvedModel,
        dispatcher: &LlmDispatcher,
    ) -> Result<InvocationResponse, InvocationError> {
        ctx.admit_snapshot(crate::catalog::InvocationToolSnapshot::synthetic_model(
            synthetic_model_facts(ctx.server, ctx.tool, model.risk),
        ))?;
        let edit = ctx.images_surface == Some(waygate_invocation::ImagesSurface::Edits);
        let body = serde_json::Value::Object(ctx.arguments.take().unwrap_or_default());
        let mut request = waygate_llm_translate::images::parse_images(body, edit)
            .map_err(|e| InvocationError::InvalidArguments(e.to_string()))?;
        request.model_requested = ctx.tool.to_owned();
        if model.route.provider != waygate_llm_credentials::LlmProvider::OpenAi
            || !model.route.openai_chatgpt
            || !model.fallbacks.is_empty()
        {
            return Err(InvocationError::InvalidArguments(
                "image models require one Codex subscription route without fallbacks".into(),
            ));
        }
        ctx.audit_category = EvidenceCategory::LlmCompletion;
        self.extract_facts(&mut ctx).await?;
        if let Some(facts) = ctx.pip_facts.as_mut() {
            facts.resource.resource_type = Some(waygate_core::MODEL_RESOURCE_TYPE.to_owned());
            facts.action.required_scope = None;
        }
        self.authorize(&mut ctx).await?;
        self.check_profile_restrictions(&mut ctx).await?;
        self.prepare_output_validation(&mut ctx).await?;
        self.check_quota(&mut ctx).await?;
        self.check_llm_budget(&ctx).await?;
        self.check_approval(&mut ctx).await?;
        self.record_pre_call(&mut ctx).await?;
        let started = std::time::Instant::now();
        // Image generation is stochastic and can consume allowance even when a
        // connection fails. Neither caching nor automatic failover applies.
        let result = dispatcher.dispatch_images(request, &model.route).await;
        ctx.latency_ms = Some(elapsed_ms(started));
        match result {
            Ok((record, body)) => {
                self.record_llm_outcome(&ctx, AuditOutcome::Success, None)
                    .await;
                self.record_llm_usage(&ctx, &record).await;
                Ok(InvocationResponse::UnaryValue(body))
            }
            Err(error) => {
                // Provider error bodies may echo prompts or uploaded content.
                // Audit and client diagnostics expose only the failure class.
                let (status, reason) = match error.provider_status() {
                    Some(status) => (status, "image provider rejected the request"),
                    None => (502, "image provider call failed; generation may have completed; request was not retried"),
                };
                self.record_llm_outcome(
                    &ctx,
                    AuditOutcome::ExecutionError,
                    Some(format!("{reason} ({status})")),
                )
                .await;
                Err(InvocationError::Upstream(ErrorData::internal_error(
                    reason,
                    Some(serde_json::json!({"image_http_status": status})),
                )))
            }
        }
    }
}
