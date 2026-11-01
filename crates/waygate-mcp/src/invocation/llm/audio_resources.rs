//! Standard provider-owned resources retain the shared model governance boundary.

use super::*;

const RESOURCE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(300);
const EVIDENCE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

impl DefaultInvocationService {
    pub(in crate::invocation) async fn invoke_audio_resource(
        &self,
        mut ctx: InvocationContext<'_>,
        model: ResolvedModel,
        dispatcher: &LlmDispatcher,
    ) -> Result<InvocationResponse, InvocationError> {
        let request = ctx
            .audio_resource
            .take()
            .expect("resource surface admitted");
        request
            .validate()
            .map_err(|message| InvocationError::InvalidArguments(message.into()))?;
        let LlmOperation::Speech(caps) = &model.operation else {
            unreachable!()
        };
        if !caps.resources.contains(&request.operation)
            || model.route.openai_chatgpt
            || model.route.embeddings_no_auth
            || !model.fallbacks.is_empty()
        {
            return Err(InvocationError::InvalidArguments(
                "audio resource operation is not supported by the configured provider".into(),
            ));
        }
        let operation = request.operation.name();
        let mut facts = synthetic_model_facts(ctx.server, ctx.tool, model.risk);
        facts.side_effects = request.operation.method() != "GET";
        ctx.admit_snapshot(crate::catalog::InvocationToolSnapshot::synthetic_model(
            facts,
        ))?;
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
        let permit = self.admit_llm_response(&ctx, dispatcher).await?;
        self.record_pre_call(&mut ctx).await?;
        let started = std::time::Instant::now();
        let mut base = llm_audit_base(&ctx);
        base.action = "AudioResource".into();
        let mut record = waygate_llm_translate::InferenceRecord::new(
            model.route.provider,
            &model.route.credential_label,
            ctx.tool,
            waygate_llm_translate::Surface::AudioResource,
            model.route.protocol,
        );
        record.usage = Default::default();
        let (tenant, _, principal) = cache_identity(&ctx);
        let row = build_usage_row(&record, tenant, principal, ctx.tool.to_owned(), None);
        let evidence = ResourceEvidence {
            audit: self.audit.clone(),
            base,
            operation,
            finished: false,
            started,
            usage: self.llm_usage.clone(),
            row,
        };
        let result = tokio::time::timeout(
            RESOURCE_DEADLINE,
            dispatcher.dispatch_audio_resource(request, &model.route),
        )
        .await;
        drop(permit);
        let (outcome, status, retry_after) = match &result {
            Ok(Ok(_)) => ("provider_complete", 200, None),
            Ok(Err(error)) => {
                let status = error.provider_status().unwrap_or(502);
                (
                    if matches!(status, 429 | 503) {
                        "provider_overload"
                    } else {
                        "provider_failed"
                    },
                    status,
                    error.provider_retry_after_seconds(),
                )
            }
            Err(_) => ("deadline_exceeded", 504, None),
        };
        evidence.finish(outcome, status == 200).await;
        match result {
            Ok(Ok(body)) => Ok(InvocationResponse::UnaryValue(body)),
            _ => Err(InvocationError::Upstream(ErrorData::internal_error(
                "audio resource request failed; operation was not retried",
                Some(
                    serde_json::json!({"audio_http_status":status,"retry_after_seconds":retry_after}),
                ),
            ))),
        }
    }
}

struct ResourceEvidence {
    audit: SharedEvidence,
    base: AuditEvent,
    operation: &'static str,
    finished: bool,
    started: std::time::Instant,
    usage: Option<crate::usage::SharedLlmUsage>,
    row: crate::usage::LlmUsageRow,
}

impl ResourceEvidence {
    async fn finish(mut self, outcome: &'static str, complete: bool) {
        self.finished = true;
        self.base.outcome = if complete {
            AuditOutcome::Success
        } else {
            AuditOutcome::ExecutionError
        };
        self.base.reason = Some(serde_json::json!({"operation":self.operation,"outcome":outcome,"provider_cancellation_confirmed":false}).to_string());
        self.base.latency_ms = Some(elapsed_ms(self.started));
        self.row.latency_ms = self.base.latency_ms;
        self.row.finish_reason = Some(format!("{}:{outcome}", self.operation));
        let finalize = async {
            self.audit
                .record_chained_best_effort(self.base.clone())
                .await;
            if let Some(usage) = &self.usage {
                usage.record_usage(self.row.clone()).await;
            }
        };
        if tokio::time::timeout(EVIDENCE_DEADLINE, finalize)
            .await
            .is_err()
        {
            tracing::warn!("audio resource evidence finalization exceeded its deadline");
        }
    }
}

impl Drop for ResourceEvidence {
    fn drop(&mut self) {
        if !self.finished {
            let mut event = self.base.clone();
            event.outcome = AuditOutcome::ExecutionError;
            event.reason = Some(serde_json::json!({"operation":self.operation,"outcome":"abandoned","provider_cancellation_confirmed":false}).to_string());
            let audit = self.audit.clone();
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(record_resource_evidence(audit, event));
            }
        }
    }
}

async fn record_resource_evidence(audit: SharedEvidence, event: AuditEvent) {
    if tokio::time::timeout(EVIDENCE_DEADLINE, audit.record_chained_best_effort(event))
        .await
        .is_err()
    {
        tracing::warn!("audio resource evidence exceeded its deadline");
    }
}
