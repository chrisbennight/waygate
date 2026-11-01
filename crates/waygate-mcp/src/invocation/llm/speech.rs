//! Governed speech delivery with bounded buffering and independent generation deadlines.

use super::*;
use base64::Engine;
use bytes::Bytes;
use serde_json::Value;
use waygate_llm_dispatch::SpeechResponse;
use waygate_llm_translate::speech::SpeechRequest;

use waygate_llm_dispatch::MAX_AUDIO_RESPONSE_BYTES;
const MAX_SPEECH_TIME: std::time::Duration = std::time::Duration::from_secs(300);
const EVIDENCE_FINALIZATION_TIME: std::time::Duration = std::time::Duration::from_secs(5);
const DELIVERY_CHUNK: usize = 64 * 1024;

impl DefaultInvocationService {
    pub(in crate::invocation) async fn invoke_speech(
        &self,
        mut ctx: InvocationContext<'_>,
        model: ResolvedModel,
        dispatcher: &LlmDispatcher,
    ) -> Result<InvocationResponse, InvocationError> {
        let LlmOperation::Speech(caps) = &model.operation else {
            unreachable!()
        };
        let request = SpeechRequest::parse(ctx.arguments.take().unwrap_or_default(), caps)
            .map_err(|e| InvocationError::InvalidArguments(e.to_string()))?;
        if model.route.openai_chatgpt
            || model.route.embeddings_no_auth
            || !model.fallbacks.is_empty()
        {
            return Err(InvocationError::InvalidArguments(
                "speech requires one standard bearer provider route without fallbacks".into(),
            ));
        }
        let media_type = if request.sse {
            "text/event-stream"
        } else {
            request.format.media_type()
        };
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
        self.check_llm_budget(&ctx).await?;
        self.check_approval(&mut ctx).await?;
        let permit = self.admit_llm_response(&ctx, dispatcher).await?;
        self.record_pre_call(&mut ctx).await?;
        let started = std::time::Instant::now();
        let base = llm_audit_base(&ctx);
        let mut record = waygate_llm_translate::InferenceRecord::new(
            model.route.provider,
            &model.route.credential_label,
            ctx.tool,
            waygate_llm_translate::Surface::AudioSpeech,
            model.route.protocol,
        );
        record.usage = Default::default();
        let (tenant, _, principal) = cache_identity(&ctx);
        let evidence = SpeechEvidence {
            audit: self.audit.clone(),
            base: base.clone(),
            started,
            finished: false,
            usage: self.llm_usage.clone(),
            record,
            tenant,
            principal,
            bytes: 0,
            first_audio_ms: None,
        };
        let response = match tokio::time::timeout(
            MAX_SPEECH_TIME,
            dispatcher.dispatch_speech(request, &model.route),
        )
        .await
        {
            Ok(Ok(response)) => response,
            result => {
                let (status, retry_after) = match &result {
                    Ok(Err(error)) => (
                        error.provider_status().unwrap_or(502),
                        error.provider_retry_after_seconds(),
                    ),
                    _ => (504, None),
                };
                let outcome = match status {
                    429 | 503 => "provider_overload",
                    504 => "deadline_exceeded",
                    _ => "dispatch_failed",
                };
                drop(permit);
                evidence.finalize(outcome, false).await;
                return Err(speech_error(
                    "speech provider request failed; generation was not retried",
                    status,
                    retry_after,
                ));
            }
        };
        Ok(deliver_speech(response, evidence, permit, media_type))
    }
}

fn speech_error(message: &'static str, status: u16, retry_after: Option<u64>) -> InvocationError {
    InvocationError::Upstream(ErrorData::internal_error(
        message,
        Some(serde_json::json!({
            "speech_http_status": status, "retry_after_seconds": retry_after,
        })),
    ))
}

struct SpeechEvidence {
    audit: SharedEvidence,
    base: AuditEvent,
    started: std::time::Instant,
    finished: bool,
    usage: Option<crate::usage::SharedLlmUsage>,
    record: waygate_llm_translate::InferenceRecord,
    tenant: String,
    principal: Option<String>,
    bytes: usize,
    first_audio_ms: Option<i64>,
}

impl SpeechEvidence {
    async fn finalize(self, outcome: &'static str, complete: bool) {
        if tokio::time::timeout(EVIDENCE_FINALIZATION_TIME, self.finish(outcome, complete))
            .await
            .is_err()
        {
            tracing::warn!("speech evidence finalization exceeded its deadline");
        }
    }

    async fn finish(mut self, outcome: &'static str, complete: bool) {
        self.finished = true;
        let mut event = self.base.clone();
        event.action = "SpeechGeneration".into();
        event.outcome = if complete {
            AuditOutcome::Success
        } else {
            AuditOutcome::ExecutionError
        };
        event.reason = Some(
            serde_json::json!({
                "operation":"audio_speech", "outcome":outcome, "audio_bytes":self.bytes,
                "first_audio_ms":self.first_audio_ms, "provider_complete":complete,
                "provider_cancellation_confirmed":false,
            })
            .to_string(),
        );
        self.audit
            .record_chained_best_effort(event.with_latency_ms(elapsed_ms(self.started)))
            .await;
        if let Some(sink) = &self.usage {
            let mut row = build_usage_row(
                &self.record,
                self.tenant.clone(),
                self.principal.clone(),
                self.record.model_requested.clone(),
                Some(elapsed_ms(self.started)),
            );
            row.finish_reason = Some(outcome.into());
            sink.record_usage(row).await;
        }
    }
}

impl Drop for SpeechEvidence {
    fn drop(&mut self) {
        if !self.finished {
            let mut event = self.base.clone();
            event.action = "SpeechGeneration".into();
            event.outcome = AuditOutcome::ExecutionError;
            event.reason =
                Some("speech generation abandoned; provider cancellation unconfirmed".into());
            let audit = self.audit.clone();
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    record_speech_evidence(audit, event).await;
                });
            }
        }
    }
}

fn deliver_speech(
    response: SpeechResponse,
    mut evidence: SpeechEvidence,
    permit: tokio::sync::OwnedSemaphorePermit,
    media_type: &'static str,
) -> InvocationResponse {
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    let (completion_sender, completion) = tokio::sync::oneshot::channel();
    let audit = evidence.audit.clone();
    let mut delivery_event = evidence.base.clone();
    delivery_event.id = uuid::Uuid::now_v7();
    delivery_event.action = "SpeechDelivery".into();
    let deadline =
        tokio::time::Instant::now() + MAX_SPEECH_TIME.saturating_sub(evidence.started.elapsed());
    tokio::spawn(async move {
        let send = async {
            let mut response = response;
            let mut saw_audio = false;
            let mut wire_bytes = 0usize;
            loop {
                let (data, terminal, audio_bytes) = match &mut response {
                    SpeechResponse::Audio(stream) => match stream.next().await {
                        Some(Ok(bytes)) => {
                            let len = bytes.len();
                            (bytes, false, len)
                        }
                        Some(Err(_)) => return Err("incomplete_audio"),
                        None if saw_audio => return Ok(()),
                        None => return Err("empty_audio"),
                    },
                    SpeechResponse::Events(stream) => {
                        let frame = match stream.next().await {
                            Some(Ok(frame)) => frame,
                            _ => return Err("incomplete_events"),
                        };
                        let value: Value =
                            serde_json::from_str(&frame.data).map_err(|_| "invalid_event")?;
                        let (terminal, audio_bytes) =
                            match value.get("type").and_then(Value::as_str) {
                                Some("speech.audio.delta") => {
                                    let audio = value
                                        .get("audio")
                                        .and_then(Value::as_str)
                                        .ok_or("invalid_audio_event")?;
                                    let bytes = base64::engine::general_purpose::STANDARD
                                        .decode(audio)
                                        .map_err(|_| "invalid_audio_event")?;
                                    (false, bytes.len())
                                }
                                Some("speech.audio.done") if saw_audio => (true, 0),
                                _ => return Err("invalid_event"),
                            };
                        // Compact JSON preserves valid SSE framing for multiline provider data.
                        // Provider usage fields are not treated as measured accounting.
                        (
                            Bytes::from(format!("data: {value}\n\n")),
                            terminal,
                            audio_bytes,
                        )
                    }
                };
                if audio_bytes > MAX_AUDIO_RESPONSE_BYTES.saturating_sub(evidence.bytes) {
                    return Err("audio_limit");
                }
                wire_bytes = wire_bytes.checked_add(data.len()).ok_or("audio_limit")?;
                if wire_bytes > MAX_AUDIO_RESPONSE_BYTES * 2 {
                    return Err("audio_limit");
                }
                evidence.bytes += audio_bytes;
                if audio_bytes > 0 {
                    saw_audio = true;
                    evidence
                        .first_audio_ms
                        .get_or_insert_with(|| elapsed_ms(evidence.started));
                }
                for chunk in data.chunks(DELIVERY_CHUNK) {
                    sender
                        .send(Ok(Bytes::copy_from_slice(chunk)))
                        .await
                        .map_err(|_| "client_disconnected")?;
                }
                if terminal {
                    return Ok(());
                }
            }
        };
        let result = tokio::select! {
            _ = sender.closed() => Err("client_disconnected"),
            result = tokio::time::timeout_at(deadline, send) => result.unwrap_or(Err("deadline_exceeded")),
        };
        let outcome = match result {
            Ok(()) => "provider_complete",
            Err(reason) => reason,
        };
        drop(permit);
        evidence.finalize(outcome, result.is_ok()).await;
        // Completion has its own slot so a full data queue cannot hide failure.
        let _ = completion_sender.send(result);
    });
    let body = delivery_stream(receiver, completion, audit, delivery_event);
    InvocationResponse::Media { media_type, body }
}

fn delivery_stream(
    receiver: tokio::sync::mpsc::Receiver<Result<Bytes, InvocationError>>,
    completion: tokio::sync::oneshot::Receiver<Result<(), &'static str>>,
    audit: SharedEvidence,
    event: AuditEvent,
) -> futures::stream::BoxStream<'static, Result<Bytes, InvocationError>> {
    struct Delivery {
        receiver: tokio::sync::mpsc::Receiver<Result<Bytes, InvocationError>>,
        completion: Option<tokio::sync::oneshot::Receiver<Result<(), &'static str>>>,
        audit: SharedEvidence,
        event: AuditEvent,
        finished: bool,
    }
    impl Drop for Delivery {
        fn drop(&mut self) {
            if !self.finished {
                let mut event = self.event.clone();
                event.outcome = AuditOutcome::ExecutionError;
                event.reason = Some(
                    "speech delivery abandoned; playback and provider cancellation unconfirmed"
                        .into(),
                );
                let audit = self.audit.clone();
                if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                    runtime.spawn(async move {
                        record_speech_evidence(audit, event).await;
                    });
                }
            }
        }
    }
    futures::stream::unfold(
        Delivery {
            receiver,
            completion: Some(completion),
            audit,
            event,
            finished: false,
        },
        |mut state| async move {
            if state.finished {
                return None;
            }
            if let Some(chunk) = state.receiver.recv().await {
                return Some((chunk, state));
            }
            let complete = matches!(
                state.completion.take().expect("one completion").await,
                Ok(Ok(()))
            );
            state.finished = true;
            let mut event = state.event.clone();
            event.outcome = if complete {
                AuditOutcome::Success
            } else {
                AuditOutcome::ExecutionError
            };
            event.reason = Some(
                if complete {
                    "HTTP response body consumed; client playback unconfirmed"
                } else {
                    "incomplete HTTP speech body"
                }
                .into(),
            );
            record_speech_evidence(state.audit.clone(), event).await;
            if complete {
                None
            } else {
                Some((
                    Err(speech_error("speech stream incomplete", 502, None)),
                    state,
                ))
            }
        },
    )
    .boxed()
}

async fn record_speech_evidence(audit: SharedEvidence, event: AuditEvent) {
    if tokio::time::timeout(
        EVIDENCE_FINALIZATION_TIME,
        audit.record_chained_best_effort(event),
    )
    .await
    .is_err()
    {
        tracing::warn!("speech lifecycle evidence exceeded its deadline");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::InMemorySink;

    #[tokio::test(start_paused = true)]
    async fn unread_speech_releases_processing_capacity_at_its_deadline() {
        let sink = Arc::new(InMemorySink::default());
        let capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = capacity.clone().acquire_owned().await.unwrap();
        let base = AuditEvent::new("SpeechGeneration", AuditOutcome::Success);
        let evidence = SpeechEvidence {
            audit: sink.clone(),
            base,
            started: std::time::Instant::now(),
            finished: false,
            usage: None,
            record: waygate_llm_translate::InferenceRecord::new(
                waygate_llm_credentials::LlmProvider::OpenAi,
                "TEST",
                "speech",
                waygate_llm_translate::Surface::AudioSpeech,
                waygate_llm_translate::UpstreamProtocol::OpenAiChat,
            ),
            tenant: "default".into(),
            principal: None,
            bytes: 0,
            first_audio_ms: None,
        };
        let InvocationResponse::Media { mut body, .. } = deliver_speech(
            SpeechResponse::Audio(futures::stream::pending().boxed()),
            evidence,
            permit,
            "audio/pcm",
        ) else {
            unreachable!()
        };
        tokio::task::yield_now().await;
        assert_eq!(capacity.available_permits(), 0);
        tokio::time::advance(MAX_SPEECH_TIME).await;
        tokio::task::yield_now().await;
        assert_eq!(capacity.available_permits(), 1);
        assert!(body.next().await.unwrap().is_err());
        assert!(sink.snapshot().await.iter().any(|event| event
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("deadline_exceeded"))));
    }

    #[tokio::test]
    async fn a_full_data_queue_does_not_hide_terminal_failure() {
        let sink = Arc::new(InMemorySink::default());
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        sender
            .send(Ok(Bytes::from_static(b"partial audio")))
            .await
            .unwrap();
        let (done, completion) = tokio::sync::oneshot::channel();
        done.send(Err("incomplete_audio")).unwrap();
        drop(sender);
        let mut stream = delivery_stream(
            receiver,
            completion,
            sink.clone(),
            AuditEvent::new("SpeechDelivery", AuditOutcome::Success),
        );
        assert!(stream.next().await.unwrap().is_ok());
        assert!(stream.next().await.unwrap().is_err());
        assert!(stream.next().await.is_none());
        assert!(sink
            .snapshot()
            .await
            .iter()
            .all(|event| event.outcome == AuditOutcome::ExecutionError));
    }
}
