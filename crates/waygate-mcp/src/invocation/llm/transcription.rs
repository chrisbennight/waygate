//! Governed completed-file transcription with one provider attempt and
//! metadata-only evidence.

use super::*;
use futures::StreamExt;
use waygate_llm_dispatch::TranscriptionBody;
use waygate_llm_translate::transcription::TranscriptionRequest;

const TRANSCRIPTION_DEADLINE: std::time::Duration = std::time::Duration::from_secs(300);
const EVIDENCE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

impl DefaultInvocationService {
    pub(in crate::invocation) async fn invoke_transcription(
        &self,
        mut ctx: InvocationContext<'_>,
        model: ResolvedModel,
        dispatcher: &LlmDispatcher,
    ) -> Result<InvocationResponse, InvocationError> {
        let LlmOperation::Transcription(caps) = &model.operation else {
            unreachable!()
        };
        let input = ctx
            .transcription
            .take()
            .expect("transcription surface admitted");
        let upload_bytes = input.upload.bytes.len();
        let request = TranscriptionRequest::parse(input, caps)
            .map_err(|e| InvocationError::InvalidArguments(e.to_string()))?;
        if model.route.openai_chatgpt
            || model.route.embeddings_no_auth
            || !model.fallbacks.is_empty()
        {
            return Err(InvocationError::InvalidArguments(
                "transcription requires one standard bearer provider route without fallbacks"
                    .into(),
            ));
        }
        ctx.admit_snapshot(crate::catalog::InvocationToolSnapshot::synthetic_model(
            synthetic_model_facts(ctx.server, ctx.tool, model.risk),
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
        // Spending budgets count tokens and cost. Transcription reports neither,
        // so its cost is zero and budgets do not gate it.
        self.check_approval(&mut ctx).await?;
        let permit = self.admit_llm_response(&ctx, dispatcher).await?;
        self.record_pre_call(&mut ctx).await?;
        let started = std::time::Instant::now();
        let mut base = llm_audit_base(&ctx);
        base.action = "AudioTranscription".into();
        let mut record = waygate_llm_translate::InferenceRecord::new(
            model.route.provider,
            &model.route.credential_label,
            ctx.tool,
            waygate_llm_translate::Surface::AudioTranscription,
            model.route.protocol,
        );
        record.usage = Default::default();
        let (tenant, _, principal) = cache_identity(&ctx);
        let row = build_usage_row(&record, tenant, principal, ctx.tool.to_owned(), None);
        let format = request.format;
        let evidence = TranscriptionEvidence {
            audit: self.audit.clone(),
            base,
            format: format.as_str(),
            upload_bytes,
            finished: false,
            started,
            usage: self.llm_usage.clone(),
            row,
        };
        let result = tokio::time::timeout(
            TRANSCRIPTION_DEADLINE,
            dispatcher.dispatch_transcription(request, &model.route),
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
            Ok(Ok(TranscriptionBody::Json(body))) => Ok(InvocationResponse::UnaryValue(body)),
            Ok(Ok(TranscriptionBody::Text(text))) => Ok(InvocationResponse::Media {
                media_type: format.media_type(),
                body: futures::stream::once(async move { Ok(bytes::Bytes::from(text)) }).boxed(),
            }),
            _ => {
                let message = match status {
                    429 | 503 => "transcription provider is busy; retry with backoff",
                    413 => "audio file exceeds the transcription provider's size limit",
                    400..=499 if !matches!(status, 401 | 403) => {
                        "transcription provider rejected the audio or request options"
                    }
                    504 => "transcription provider did not respond in time",
                    _ => "transcription provider request failed",
                };
                Err(InvocationError::Upstream(ErrorData::internal_error(
                    message,
                    Some(
                        serde_json::json!({"audio_http_status":status,"retry_after_seconds":retry_after}),
                    ),
                )))
            }
        }
    }
}

struct TranscriptionEvidence {
    audit: SharedEvidence,
    base: AuditEvent,
    format: &'static str,
    upload_bytes: usize,
    finished: bool,
    started: std::time::Instant,
    usage: Option<crate::usage::SharedLlmUsage>,
    row: crate::usage::LlmUsageRow,
}

impl TranscriptionEvidence {
    fn reason(&self, outcome: &str) -> String {
        serde_json::json!({
            "operation":"audio_transcription", "outcome":outcome,
            "upload_bytes":self.upload_bytes, "response_format":self.format,
            "provider_cancellation_confirmed":false,
        })
        .to_string()
    }

    async fn finish(mut self, outcome: &'static str, complete: bool) {
        self.finished = true;
        self.base.outcome = if complete {
            AuditOutcome::Success
        } else {
            AuditOutcome::ExecutionError
        };
        self.base.reason = Some(self.reason(outcome));
        self.base.latency_ms = Some(elapsed_ms(self.started));
        self.row.latency_ms = self.base.latency_ms;
        self.row.finish_reason = Some(outcome.into());
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
            tracing::warn!("transcription evidence finalization exceeded its deadline");
        }
    }
}

impl Drop for TranscriptionEvidence {
    fn drop(&mut self) {
        if !self.finished {
            let mut event = self.base.clone();
            event.outcome = AuditOutcome::ExecutionError;
            event.reason = Some(self.reason("abandoned"));
            let audit = self.audit.clone();
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    if tokio::time::timeout(
                        EVIDENCE_DEADLINE,
                        audit.record_chained_best_effort(event),
                    )
                    .await
                    .is_err()
                    {
                        tracing::warn!("transcription evidence exceeded its deadline");
                    }
                });
            }
        }
    }
}
