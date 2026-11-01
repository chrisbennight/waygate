//! Bounded standard Realtime sessions and provider-owned WebRTC calls.

use super::*;
use futures::{channel::mpsc, SinkExt};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use tokio_util::sync::CancellationToken;
use waygate_core::realtime::{RealtimeCapabilities, RealtimeRequest, MAX_REALTIME_EVENT_BYTES};
use waygate_llm_dispatch::{RealtimeCallControl, RealtimeMessage, RealtimeSocket};

const SETUP_TIME: std::time::Duration = std::time::Duration::from_secs(30);
const IO_TIME: std::time::Duration = std::time::Duration::from_secs(5);
const MAX_RESPONSES: usize = 128;
const MAX_SESSION_BYTES: usize = 256 * 1024 * 1024;
const MAX_SESSION_EVENTS: usize = 100_000;

impl DefaultInvocationService {
    pub(in crate::invocation) async fn invoke_realtime(
        &self,
        mut ctx: InvocationContext<'_>,
        model: ResolvedModel,
        dispatcher: &LlmDispatcher,
    ) -> Result<InvocationResponse, InvocationError> {
        let LlmOperation::Realtime(caps) = &model.operation else {
            unreachable!()
        };
        let mut request = ctx.realtime.take().expect("Realtime surface admitted");
        if model.route.openai_chatgpt
            || model.route.embeddings_no_auth
            || !model.fallbacks.is_empty()
        {
            return Err(InvocationError::InvalidArguments(
                "Realtime requires one standard bearer route without fallbacks".into(),
            ));
        }
        match &mut request {
            RealtimeRequest::WebSocket if !caps.websocket => {
                return Err(invalid("WebSocket is not enabled for this model"))
            }
            RealtimeRequest::WebRtc { session, .. } => {
                if !caps.webrtc {
                    return Err(invalid("WebRTC is not enabled for this model"));
                }
                caps.validate_session(session).map_err(invalid)?;
                session["model"] = Value::String(model.route.upstream_model.clone());
            }
            RealtimeRequest::Hangup { call_id }
                if !caps.webrtc
                    || call_id.is_empty()
                    || call_id.len() > 512
                    || matches!(call_id.as_str(), "." | "..")
                    || call_id.chars().any(char::is_control) =>
            {
                return Err(invalid("invalid Realtime call identifier"));
            }
            _ => {}
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
        let hangup = matches!(request, RealtimeRequest::Hangup { .. });
        if !hangup {
            self.check_llm_budget(&ctx).await?;
        }
        self.check_approval(&mut ctx).await?;
        let permit = if hangup {
            self.admit_llm_response(&ctx, dispatcher).await?
        } else {
            dispatcher
                .try_admit_realtime_session()
                .ok_or_else(|| realtime_error(429))?
        };
        self.record_pre_call(&mut ctx).await?;
        let (tenant, _, principal) = cache_identity(&ctx);
        let mut record = waygate_llm_translate::InferenceRecord::new(
            model.route.provider,
            &model.route.credential_label,
            ctx.tool,
            waygate_llm_translate::Surface::Realtime,
            model.route.protocol,
        );
        record.usage = Default::default();
        let mut evidence = SessionEvidence {
            audit: self.audit.clone(),
            base: llm_audit_base(&ctx),
            started: std::time::Instant::now(),
            finished: false,
            usage: self.llm_usage.clone(),
            record,
            tenant: tenant.clone(),
            principal: principal.clone(),
            responses: Vec::new(),
            response_ids: BTreeMap::new(),
            pending: 0,
            provider_errors: 0,
            overloads: 0,
            truncations: 0,
            bytes: 0,
            events: 0,
            measured_usage: caps.measured_usage,
            transport: if matches!(request, RealtimeRequest::WebSocket) {
                "websocket"
            } else {
                "webrtc"
            },
        };
        if let RealtimeRequest::Hangup { call_id } = request {
            let result = tokio::time::timeout(
                SETUP_TIME,
                dispatcher.hangup_realtime_call(&model.route, &call_id),
            )
            .await;
            drop(permit);
            let confirmed = matches!(result, Ok(Ok(())));
            evidence
                .finish(
                    if confirmed {
                        "hangup_confirmed"
                    } else {
                        "hangup_unconfirmed"
                    },
                    confirmed,
                )
                .await;
            return if confirmed {
                Ok(InvocationResponse::UnaryValue(Value::Null))
            } else {
                Err(realtime_error(502))
            };
        }
        let permit = Arc::new(permit);
        let mut cleanup = CallCleanup(None);
        let setup = async {
            match request {
                RealtimeRequest::WebSocket => dispatcher
                    .connect_realtime(&model.route)
                    .await
                    .map(|socket| (socket, None)),
                RealtimeRequest::WebRtc { sdp, session } => {
                    let call = dispatcher
                        .create_realtime_call(&model.route, sdp, session)
                        .await?;
                    cleanup.0 = Some(call.control);
                    // Install cleanup before reading a potentially stalled or failed SDP body.
                    let answer = call.answer.await?;
                    let socket = cleanup
                        .0
                        .as_ref()
                        .expect("known provider call")
                        .connect_sideband()
                        .await?;
                    Ok((socket, Some(answer)))
                }
                RealtimeRequest::Hangup { .. } => unreachable!(),
            }
        };
        let (socket, answer) = match tokio::time::timeout(SETUP_TIME, setup).await {
            Ok(Ok(result)) => result,
            result => {
                let status = match result {
                    Ok(Err(error)) => error.provider_status().unwrap_or(502),
                    _ => 504,
                };
                drop(permit);
                let confirmed = cleanup.finish().await;
                evidence
                    .finish(
                        if matches!(status, 429 | 503) {
                            "provider_overload"
                        } else {
                            "setup_failed"
                        },
                        confirmed,
                    )
                    .await;
                return Err(realtime_error(status));
            }
        };
        let guard = SessionPolicy {
            authz: self.authz.clone(),
            facts: ctx.pip_facts.clone(),
            budget: self.llm_budget.clone(),
            tenant,
            principal,
            alias: ctx.tool.to_owned(),
        };
        let cancel = CancellationToken::new();
        let (commands, command_rx) = mpsc::channel(1);
        let (events_tx, events_rx) = mpsc::channel(1);
        let rtc = answer.is_some();
        let result = if let Some(sdp) = answer {
            InvocationResponse::RealtimeCall {
                call_id: cleanup
                    .0
                    .as_ref()
                    .expect("WebRTC provider call")
                    .call_id()
                    .to_owned(),
                sdp,
                delivery_guard: cancel.clone().drop_guard(),
            }
        } else {
            let delivery_guard = cancel.clone().drop_guard();
            let stream = async_stream_events(events_rx, delivery_guard, permit.clone());
            InvocationResponse::Realtime {
                commands,
                events: stream,
            }
        };
        let config = SessionConfig {
            caps: caps.clone(),
            alias: ctx.tool.to_owned(),
            upstream_model: model.route.upstream_model,
        };
        tokio::spawn(async move {
            let mut socket = socket;
            let deadline = tokio::time::Instant::now()
                + std::time::Duration::from_secs(config.caps.max_session_seconds)
                    .saturating_sub(evidence.started.elapsed());
            let outcome = tokio::select! {
                _ = cancel.cancelled() => "client_disconnected",
                _ = tokio::time::sleep_until(deadline) => "session_deadline",
                outcome = run_session(&mut socket, (!rtc).then_some(command_rx), (!rtc).then_some(events_tx), &config, &guard, &mut evidence) => outcome,
            };
            let _ =
                tokio::time::timeout(std::time::Duration::from_secs(1), socket.close(None)).await;
            drop(socket);
            drop(permit);
            let confirmed = cleanup.finish().await;
            evidence.finish(outcome, confirmed).await;
        });
        Ok(result)
    }
}

fn invalid(message: &'static str) -> InvocationError {
    InvocationError::InvalidArguments(message.into())
}
fn realtime_error(status: u16) -> InvocationError {
    InvocationError::Upstream(ErrorData::internal_error(
        "Realtime request failed; session creation was not retried",
        Some(json!({"realtime_http_status":status})),
    ))
}

fn async_stream_events(
    receiver: mpsc::Receiver<Result<Value, InvocationError>>,
    guard: tokio_util::sync::DropGuard,
    permit: Arc<tokio::sync::OwnedSemaphorePermit>,
) -> futures::stream::BoxStream<'static, Result<Value, InvocationError>> {
    // The adapter holds capacity while sending an event, even after provider EOF.
    futures::stream::unfold(
        (receiver, guard, permit),
        |(mut receiver, guard, permit)| async move {
            receiver
                .next()
                .await
                .map(|item| (item, (receiver, guard, permit)))
        },
    )
    .boxed()
}

struct CallCleanup(Option<RealtimeCallControl>);
impl CallCleanup {
    async fn finish(&mut self) -> bool {
        let Some(control) = self.0.take() else {
            return false;
        };
        matches!(
            tokio::time::timeout(IO_TIME, control.hangup()).await,
            Ok(Ok(()))
        )
    }
}
impl Drop for CallCleanup {
    fn drop(&mut self) {
        if let Some(control) = self.0.take() {
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    if !matches!(
                        tokio::time::timeout(IO_TIME, control.hangup()).await,
                        Ok(Ok(()))
                    ) {
                        tracing::warn!("Realtime setup cleanup unconfirmed");
                    }
                });
            }
        }
    }
}

struct SessionPolicy {
    authz: SharedAuthz,
    facts: Option<waygate_core::Facts>,
    budget: Option<crate::budget::SharedLlmBudgetGate>,
    tenant: String,
    principal: Option<String>,
    alias: String,
}
impl SessionPolicy {
    async fn allowed(&self) -> bool {
        let check = async {
            if let Some(facts) = &self.facts {
                if !matches!(
                    self.authz.authorize_tool_call(facts).await,
                    AuthzVerdict::Allow { .. }
                ) {
                    return false;
                }
            }
            if let Some(budget) = &self.budget {
                if budget
                    .check(&self.tenant, self.principal.as_deref(), &self.alias)
                    .await
                    .is_some()
                {
                    return false;
                }
            }
            true
        };
        tokio::time::timeout(IO_TIME, check).await.unwrap_or(false)
    }
}

struct SessionConfig {
    caps: RealtimeCapabilities,
    alias: String,
    upstream_model: String,
}

async fn forward(
    sender: &mut Option<mpsc::Sender<Result<Value, InvocationError>>>,
    value: Value,
) -> Result<(), &'static str> {
    if let Some(sender) = sender {
        match tokio::time::timeout(IO_TIME, sender.send(Ok(value))).await {
            Ok(Ok(())) => {}
            _ => return Err("client_delivery_failed"),
        }
    }
    Ok(())
}

async fn run_session(
    socket: &mut RealtimeSocket,
    mut commands: Option<mpsc::Receiver<Value>>,
    mut events: Option<mpsc::Sender<Result<Value, InvocationError>>>,
    config: &SessionConfig,
    policy: &SessionPolicy,
    evidence: &mut SessionEvidence,
) -> &'static str {
    let mut tick = tokio::time::interval(IO_TIME);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tick.tick() => { if !policy.allowed().await { return "policy_or_budget_revoked" } }
            command = async { match &mut commands { Some(receiver) => receiver.next().await, None => futures::future::pending().await } } => {
                let Some(mut command) = command else { return "client_disconnected" };
                let size = command.to_string().len();
                if evidence.bound(size).is_err() { return "session_limit" }
                if let Err(message) = config.caps.validate_client_event(&command, &config.alias, &config.upstream_model) {
                    if let Err(outcome) = forward(&mut events, json!({"type":"error","event_id":format!("event_{}",uuid::Uuid::now_v7()),"error":{"type":"invalid_request_error","code":"invalid_request","message":message,"param":null}})).await { return outcome }
                    continue;
                }
                let kind = command["type"].as_str().unwrap_or_default();
                if matches!(kind, "response.create" | "session.update") && !policy.allowed().await { return "policy_or_budget_revoked" }
                if kind == "response.create" {
                    if evidence.pending + evidence.responses.len() >= MAX_RESPONSES { return "response_limit" }
                    evidence.pending += 1;
                }
                if kind == "session.update" && command["session"].get("model").is_some() {
                    command["session"]["model"] = Value::String(config.upstream_model.clone());
                }
                match tokio::time::timeout(IO_TIME, socket.send(RealtimeMessage::Text(command.to_string().into()))).await {
                    Ok(Ok(())) => {}, _ => return "provider_write_failed",
                }
            }
            message = socket.next() => {
                let text = match message {
                    Some(Ok(RealtimeMessage::Text(text))) => text,
                    Some(Ok(RealtimeMessage::Ping(bytes))) => {
                        if !matches!(tokio::time::timeout(IO_TIME,socket.send(RealtimeMessage::Pong(bytes))).await,Ok(Ok(()))) { return "provider_write_failed" }
                        continue;
                    }
                    Some(Ok(RealtimeMessage::Pong(_))) => continue,
                    Some(Ok(RealtimeMessage::Close(_))) | None => return "provider_closed",
                    _ => return "provider_protocol_failed",
                };
                if evidence.bound(text.len()).is_err() { return "session_limit" }
                let value: Value = match serde_json::from_str(&text) { Ok(value) => value, Err(_) => return "provider_protocol_failed" };
                if let Err(outcome) = evidence.observe(&value) { return outcome }
                if let Err(outcome) = forward(&mut events, value).await { return outcome }
            }
        }
    }
}

struct ResponseEvidence {
    started: std::time::Instant,
    first_audio_ms: Option<i64>,
    complete_ms: Option<i64>,
    status: &'static str,
    counts: Option<(u64, u64)>,
    media_outcome: &'static str,
    media_end_ms: Option<i64>,
}
struct SessionEvidence {
    audit: SharedEvidence,
    base: AuditEvent,
    started: std::time::Instant,
    finished: bool,
    usage: Option<crate::usage::SharedLlmUsage>,
    record: waygate_llm_translate::InferenceRecord,
    tenant: String,
    principal: Option<String>,
    responses: Vec<ResponseEvidence>,
    response_ids: BTreeMap<String, usize>,
    pending: usize,
    provider_errors: usize,
    overloads: usize,
    truncations: usize,
    bytes: usize,
    events: usize,
    measured_usage: bool,
    transport: &'static str,
}
impl SessionEvidence {
    fn bound(&mut self, bytes: usize) -> Result<(), ()> {
        self.events += 1;
        self.bytes = self.bytes.saturating_add(bytes);
        if bytes > MAX_REALTIME_EVENT_BYTES
            || self.bytes > MAX_SESSION_BYTES
            || self.events > MAX_SESSION_EVENTS
        {
            Err(())
        } else {
            Ok(())
        }
    }
    fn observe(&mut self, event: &Value) -> Result<(), &'static str> {
        let kind = event
            .get("type")
            .and_then(Value::as_str)
            .ok_or("provider_protocol_failed")?;
        if kind == "error" {
            self.provider_errors += 1;
            if event
                .pointer("/error/code")
                .and_then(Value::as_str)
                .is_some_and(|code| {
                    matches!(
                        code,
                        "rate_limit_exceeded" | "server_overloaded" | "overloaded"
                    )
                })
            {
                self.overloads += 1;
            }
        }
        if kind == "conversation.item.truncated" {
            self.truncations += 1;
        }
        if kind == "response.created" {
            let id = event
                .pointer("/response/id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty() && id.len() <= 512)
                .ok_or("provider_protocol_failed")?;
            if self.responses.len() >= MAX_RESPONSES {
                return Err("response_limit");
            }
            if self
                .response_ids
                .insert(id.to_owned(), self.responses.len())
                .is_some()
            {
                return Err("provider_protocol_failed");
            }
            self.pending = self.pending.saturating_sub(1);
            self.responses.push(ResponseEvidence {
                started: std::time::Instant::now(),
                first_audio_ms: None,
                complete_ms: None,
                status: "unconfirmed",
                counts: None,
                media_outcome: "not_observed",
                media_end_ms: None,
            });
        } else if matches!(
            kind,
            "response.output_audio.delta"
                | "output_audio_buffer.started"
                | "output_audio_buffer.stopped"
                | "output_audio_buffer.cleared"
                | "response.done"
        ) {
            let id = if kind == "response.done" {
                event.pointer("/response/id")
            } else {
                event.get("response_id")
            }
            .and_then(Value::as_str)
            .ok_or("provider_protocol_failed")?;
            let Some(index) = self.response_ids.get(id) else {
                return Err("provider_protocol_failed");
            };
            let response = &mut self.responses[*index];
            if kind == "response.done" {
                if response.complete_ms.is_some() {
                    return Err("provider_protocol_failed");
                }
                response.complete_ms = Some(elapsed_ms(response.started));
                response.status = match event.pointer("/response/status").and_then(Value::as_str) {
                    Some("completed") => "completed",
                    Some("cancelled") => "cancelled",
                    Some("failed") => "failed",
                    Some("incomplete") => "incomplete",
                    _ => "unconfirmed",
                };
                if self.measured_usage {
                    response.counts = event
                        .pointer("/response/usage/input_tokens")
                        .and_then(Value::as_u64)
                        .zip(
                            event
                                .pointer("/response/usage/output_tokens")
                                .and_then(Value::as_u64),
                        );
                }
            } else if self.transport == "webrtc"
                && matches!(
                    kind,
                    "output_audio_buffer.stopped" | "output_audio_buffer.cleared"
                )
            {
                response.media_outcome = if kind == "output_audio_buffer.stopped" {
                    "provider_buffer_stopped"
                } else {
                    "provider_buffer_cleared"
                };
                response.media_end_ms = Some(elapsed_ms(response.started));
            } else if (kind == "output_audio_buffer.started" && self.transport == "webrtc")
                || (self.transport == "websocket"
                    && kind == "response.output_audio.delta"
                    && event
                        .get("delta")
                        .and_then(Value::as_str)
                        .is_some_and(|delta| !delta.is_empty()))
            {
                response
                    .first_audio_ms
                    .get_or_insert_with(|| elapsed_ms(response.started));
                if response.media_end_ms.is_none() {
                    response.media_outcome = if self.transport == "webrtc" {
                        "provider_media_started"
                    } else {
                        "audio_received"
                    };
                }
            }
        }
        Ok(())
    }
    async fn finish(mut self, outcome: &'static str, call_termination_confirmed: bool) {
        self.finished = true;
        let mut counts = (!self.responses.is_empty()
            && self.pending == 0
            && !matches!(
                outcome,
                "session_limit" | "response_limit" | "provider_protocol_failed"
            ))
        .then_some((0u64, 0u64));
        for response in &self.responses {
            counts = counts.and_then(|(input, output)| {
                let (next_input, next_output) = response.counts?;
                Some((
                    input.checked_add(next_input)?,
                    output.checked_add(next_output)?,
                ))
            });
        }
        if let Some((input, output)) = counts {
            self.record.usage.input = Some(input);
            self.record.usage.output = Some(output);
        }
        let mut row = build_usage_row(
            &self.record,
            self.tenant.clone(),
            self.principal.clone(),
            self.record.model_requested.clone(),
            Some(elapsed_ms(self.started)),
        );
        row.finish_reason = Some(outcome.into());
        let finalize = async {
            for (index, response) in self.responses.iter().enumerate() {
                let mut event = self.base.clone();
                event.id = uuid::Uuid::now_v7();
                event.action = "RealtimeGeneration".into();
                event.outcome = if response.status == "completed" {
                    AuditOutcome::Success
                } else {
                    AuditOutcome::ExecutionError
                };
                event.latency_ms = response.complete_ms;
                event.reason = Some(json!({"session":self.base.id,"response_index":index,"status":response.status,"transport":self.transport,"timing_origin":"gateway_received_response_created","first_audio_ms":response.first_audio_ms,"first_audio_boundary":if self.transport == "webrtc" { "provider_media_started" } else { "gateway_received_delta" },"media_outcome":response.media_outcome,"media_end_ms":response.media_end_ms,"input_tokens":response.counts.map(|c|c.0),"output_tokens":response.counts.map(|c|c.1),"usage_source":if response.counts.is_some() {"configured_measured_provider"} else {"unknown"},"provider_cancellation_confirmed":response.status == "cancelled"}).to_string());
                self.audit.record_chained_best_effort(event).await;
            }
            self.base.action = "RealtimeSession".into();
            self.base.outcome = if matches!(
                outcome,
                "hangup_confirmed" | "provider_closed" | "client_disconnected"
            ) {
                AuditOutcome::Success
            } else {
                AuditOutcome::ExecutionError
            };
            self.base.latency_ms = row.latency_ms;
            self.base.reason = Some(json!({"outcome":outcome,"transport":self.transport,"responses":self.responses.len(),"wire_bytes":self.bytes,"provider_errors":self.provider_errors,"provider_overloads":self.overloads,"observed_item_truncations":self.truncations,"call_termination_confirmed":call_termination_confirmed,"client_playback_confirmed":false}).to_string());
            self.audit
                .record_chained_best_effort(self.base.clone())
                .await;
            if let Some(usage) = &self.usage {
                usage.record_usage(row).await;
            }
        };
        if tokio::time::timeout(IO_TIME, finalize).await.is_err() {
            tracing::warn!("Realtime evidence finalization exceeded its deadline");
        }
    }
}
impl Drop for SessionEvidence {
    fn drop(&mut self) {
        if !self.finished {
            let mut event = self.base.clone();
            event.action = "RealtimeSession".into();
            event.outcome = AuditOutcome::ExecutionError;
            event.reason = Some("Realtime setup abandoned; call termination unconfirmed".into());
            let audit = self.audit.clone();
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    let _ = tokio::time::timeout(IO_TIME, audit.record_chained_best_effort(event))
                        .await;
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence() -> SessionEvidence {
        SessionEvidence {
            audit: Arc::new(crate::audit::NullSink),
            base: AuditEvent::new("RealtimeSession", AuditOutcome::Success),
            started: std::time::Instant::now(),
            finished: true,
            usage: None,
            record: waygate_llm_translate::InferenceRecord::new(
                waygate_llm_credentials::LlmProvider::OpenAi,
                "TEST",
                "live",
                waygate_llm_translate::Surface::Realtime,
                waygate_llm_translate::UpstreamProtocol::OpenAiChat,
            ),
            tenant: "default".into(),
            principal: None,
            responses: vec![],
            response_ids: BTreeMap::new(),
            pending: 0,
            provider_errors: 0,
            overloads: 0,
            truncations: 0,
            bytes: 0,
            events: 0,
            measured_usage: false,
            transport: "webrtc",
        }
    }

    #[tokio::test]
    async fn webrtc_audio_deltas_do_not_claim_provider_media_start() {
        let mut evidence = evidence();
        evidence
            .observe(&json!({"type":"response.created","response":{"id":"response"}}))
            .unwrap();
        evidence.observe(&json!({"type":"response.output_audio.delta","response_id":"response","delta":"AAAA"})).unwrap();
        assert!(evidence.responses[0].first_audio_ms.is_none());
        evidence
            .observe(&json!({"type":"output_audio_buffer.started","response_id":"response"}))
            .unwrap();
        assert!(evidence.responses[0].first_audio_ms.is_some());
        evidence
            .observe(
                &json!({"type":"response.done","response":{"id":"response","status":"completed"}}),
            )
            .unwrap();
        evidence
            .observe(&json!({"type":"output_audio_buffer.stopped","response_id":"response"}))
            .unwrap();
        assert_eq!(evidence.responses[0].status, "completed");
        assert_eq!(
            evidence.responses[0].media_outcome,
            "provider_buffer_stopped"
        );
    }

    #[tokio::test]
    async fn downstream_event_holds_capacity_after_provider_eof_until_delivery_ends() {
        for consume_eof in [false, true] {
            let capacity = Arc::new(tokio::sync::Semaphore::new(1));
            let permit = Arc::new(capacity.clone().acquire_owned().await.unwrap());
            let (mut sender, receiver) = mpsc::channel(1);
            sender
                .send(Ok(json!({"type":"response.done"})))
                .await
                .unwrap();
            drop(sender);
            let mut stream = async_stream_events(
                receiver,
                CancellationToken::new().drop_guard(),
                permit.clone(),
            );
            drop(permit);
            assert!(stream.next().await.unwrap().is_ok());
            assert!(
                capacity.clone().try_acquire_owned().is_err(),
                "sending the final event still owns a live adapter"
            );
            if consume_eof {
                assert!(stream.next().await.is_none());
            }
            drop(stream);
            assert!(capacity.try_acquire_owned().is_ok());
        }
    }

    #[tokio::test]
    async fn idle_session_expiry_retains_all_completed_measured_usage() {
        #[derive(Default)]
        struct Usage(std::sync::Mutex<Vec<crate::usage::LlmUsageRow>>);
        #[async_trait::async_trait]
        impl crate::usage::LlmUsageRecorder for Usage {
            async fn record_usage(&self, row: crate::usage::LlmUsageRow) {
                self.0.lock().unwrap().push(row);
            }
        }
        let usage = Arc::new(Usage::default());
        let mut evidence = evidence();
        evidence.measured_usage = true;
        evidence.usage = Some(usage.clone());
        evidence
            .observe(&json!({"type":"response.created","response":{"id":"response"}}))
            .unwrap();
        evidence.observe(&json!({"type":"response.done","response":{"id":"response","status":"completed","usage":{"input_tokens":5,"output_tokens":7}}})).unwrap();
        evidence.finish("session_deadline", true).await;
        let rows = usage.0.lock().unwrap();
        assert_eq!(rows[0].input_tokens, Some(5));
        assert_eq!(rows[0].output_tokens, Some(7));
    }
}
