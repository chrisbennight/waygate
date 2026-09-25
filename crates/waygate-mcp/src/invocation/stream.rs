//! Streaming finalization: cache tee, usage aggregation, replay synthesis.
//! Child module of [`super`], the fifteen-stage pipeline.

use super::llm::build_usage_row;
use super::*;

/// Keep admission through stream finalization or cancellation, including replay.
pub(super) fn hold_response_capacity(
    stream: InvocationStream,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> InvocationStream {
    Box::pin(futures::stream::unfold(
        (stream, permit),
        |(mut stream, permit)| async move { stream.next().await.map(|chunk| (chunk, (stream, permit))) },
    ))
}

/// Re-emit a stored unary OpenAI `chat.completion` `body` as a synthetic SSE
/// chunk stream, so a streaming cache hit looks like a fresh stream to the
/// client. No provider is contacted and the full body is already known, so this
/// is a pure replay that does no auditing — the hit was finalized synchronously
/// before this stream was built. Per choice it emits a role+content chunk then a
/// finish chunk, then one usage chunk (if the body carried usage), then the
/// terminal frame the egress turns into `data: [DONE]`.
pub(super) fn synthetic_replay_stream(body: serde_json::Value) -> InvocationStream {
    use serde_json::{json, Value};
    let id = body
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let model = body
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let chunk = |delta: Value, index: u64, finish_reason: Value| {
        json!({
            "id": id,
            "object": "chat.completion.chunk",
            "model": model,
            "choices": [{"index": index, "delta": delta, "finish_reason": finish_reason}],
        })
    };
    let mut chunks: Vec<InvocationChunk> = Vec::new();
    let choices = body
        .get("choices")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for (i, choice) in choices.iter().enumerate() {
        let index = i as u64;
        let msg = choice.get("message");
        let role = msg
            .and_then(|m| m.get("role"))
            .and_then(Value::as_str)
            .unwrap_or("assistant");
        let mut delta = json!({ "role": role });
        // Role + the full content in a single delta: clients concatenate
        // `delta.content` across chunks, so one content delta is a valid (if
        // coarser-grained) replay of the original token-by-token stream.
        if let Some(content) = msg.and_then(|m| m.get("content")) {
            if !content.is_null() {
                delta["content"] = content.clone();
            }
        }
        // A stored tool-call body must replay its `tool_calls` as a streamed
        // `delta.tool_calls` — otherwise a cached unary tool call replayed to a
        // streaming client (the cache key ignores transport) would arrive with
        // `finish_reason: "tool_calls"` but no call for the client to execute.
        // The unary `tool_calls[]` have no streaming `index`; add one per entry
        // and emit each whole (clients accumulate by index — one chunk carrying a
        // call's full arguments is a valid replay).
        if let Some(tool_calls) = msg
            .and_then(|m| m.get("tool_calls"))
            .and_then(Value::as_array)
        {
            delta["tool_calls"] = Value::Array(
                tool_calls
                    .iter()
                    .enumerate()
                    .map(|(ti, tc)| {
                        let mut o = tc.as_object().cloned().unwrap_or_default();
                        o.insert("index".into(), json!(ti));
                        Value::Object(o)
                    })
                    .collect(),
            );
        }
        chunks.push(InvocationChunk {
            event: chunk(delta, index, Value::Null),
            event_name: None,
            terminal: false,
        });
        // Finish chunk for this choice (empty delta + the stored finish_reason).
        let finish = choice.get("finish_reason").cloned().unwrap_or(Value::Null);
        chunks.push(InvocationChunk {
            event: chunk(json!({}), index, finish),
            event_name: None,
            terminal: false,
        });
    }
    // Usage chunk (OpenAI emits one with empty `choices`), only when the stored
    // body carried usage. Replays the original counts the client would have seen;
    // the gateway's own ledger row already recorded this as a zero-token hit.
    if let Some(usage) = body.get("usage") {
        if !usage.is_null() {
            chunks.push(InvocationChunk {
                event: json!({
                    "id": id.clone(),
                    "object": "chat.completion.chunk",
                    "model": model.clone(),
                    "choices": [],
                    "usage": usage.clone(),
                }),
                event_name: None,
                terminal: false,
            });
        }
    }
    // Terminal frame → the egress emits `data: [DONE]` (it ignores a terminal
    // chunk's event). Always present so the client sees a clean close.
    chunks.push(InvocationChunk {
        event: Value::String("[DONE]".to_owned()),
        event_name: None,
        terminal: true,
    });
    futures::stream::iter(chunks.into_iter().map(Ok)).boxed()
}

/// Snapshot the four authorization-decision INPUTS a Cedar
/// decision can branch on, sourced from the call's principal + resolved facts,
/// for the `AuditEvent::with_decision_inputs` capture on every decision row.
/// Returns `(req_scopes, auth_method, req_roles, side_effects)`:
/// - `principal.scopes` / `principal.auth_method` (wire string) /
///   `principal.roles` come from the authenticated principal;
/// - `resource.side_effects` is the resolved tool/model's mutating-surface flag.
///
/// `None` principal (anonymous dev-mode calls, where the authz gate is skipped
/// and there is no decision to replay) yields ALL FOUR absent — empty
/// scopes/roles, `None` auth_method, AND `None` side_effects — so the row's
/// decision-input columns stay fully absent, the same "no decision recorded"
/// shape a legacy row has. This is deliberate: a no-principal row can't be
/// reconstructed for exact replay (there's no principal to evaluate), so it
/// must not carry a partial side_effects-only tail that the replay reader
/// would then have to special-case — "has any decision input" cleanly means
/// "a principal-bearing decision was recorded".
pub(crate) fn decision_inputs(
    principal: Option<&Principal>,
    facts: &ToolFacts,
) -> (Vec<String>, Option<String>, Vec<String>, Option<bool>) {
    match principal {
        Some(p) => (
            p.scopes.clone(),
            Some(p.auth_method.as_str().to_owned()),
            p.roles.clone(),
            Some(facts.side_effects),
        ),
        None => (Vec::new(), None, Vec::new(), None),
    }
}

/// Per-choice accumulator for the tee-on-miss aggregator: the role, the
/// concatenated content deltas, and the finish reason, rebuilt into a
/// `chat.completion` message at clean close.
#[derive(Default)]
pub(super) struct ChoiceAcc {
    role: Option<String>,
    content: String,
    finish_reason: Option<serde_json::Value>,
}

/// Aggregates the forwarded OpenAI chunks of a streamed MISS back into the unary
/// `chat.completion` body the cache stores, so a later request (unary or
/// streaming) hits it. `unsupported` latches when a delta carries anything other
/// than `role`/`content` (e.g. `tool_calls`, `refusal`) — we then decline to
/// cache rather than store a lossy body we couldn't faithfully replay.
#[derive(Default)]
pub(super) struct StreamCacheAgg {
    id: Option<String>,
    model: Option<String>,
    choices: std::collections::BTreeMap<u64, ChoiceAcc>,
    usage: Option<serde_json::Value>,
    unsupported: bool,
    observed_bytes: usize,
}

/// Budget for cumulative serialized chunks considered by optional stream caching.
const MAX_STREAM_CACHE_BYTES: usize = 1024 * 1024;

struct CacheByteBudget(usize);

impl std::io::Write for CacheByteBudget {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.0 {
            return Err(std::io::Error::other("stream cache byte limit exceeded"));
        }
        self.0 -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl StreamCacheAgg {
    /// Fold one forwarded client chunk (an OpenAI `chat.completion.chunk` value)
    /// into the accumulator. Tolerant of non-object events (e.g. the `[DONE]`
    /// sentinel) and of chunks without choices (e.g. the usage-only chunk).
    fn observe(&mut self, event: &serde_json::Value) {
        if self.unsupported {
            return;
        }
        // Count without allocating another copy of the event. Charge complete
        // chunks so metadata, usage, choice count, and text all consume budget.
        let mut budget = CacheByteBudget(MAX_STREAM_CACHE_BYTES - self.observed_bytes);
        if serde_json::to_writer(&mut budget, event).is_err() {
            self.discard();
            return;
        }
        self.observed_bytes = MAX_STREAM_CACHE_BYTES - budget.0;
        let Some(obj) = event.as_object() else {
            return;
        };
        if self.id.is_none() {
            if let Some(id) = obj.get("id").and_then(|v| v.as_str()) {
                self.id = Some(id.to_owned());
            }
        }
        if self.model.is_none() {
            if let Some(m) = obj.get("model").and_then(|v| v.as_str()) {
                self.model = Some(m.to_owned());
            }
        }
        if let Some(u) = obj.get("usage") {
            if !u.is_null() {
                self.usage = Some(u.clone());
            }
        }
        let Some(choices) = obj.get("choices").and_then(|c| c.as_array()) else {
            return;
        };
        for choice in choices {
            let index = choice.get("index").and_then(|v| v.as_u64()).unwrap_or(0);
            let acc = self.choices.entry(index).or_default();
            if let Some(fr) = choice.get("finish_reason") {
                if !fr.is_null() {
                    acc.finish_reason = Some(fr.clone());
                }
            }
            let Some(delta) = choice.get("delta").and_then(|d| d.as_object()) else {
                continue;
            };
            for (key, value) in delta {
                match key.as_str() {
                    "role" => {
                        if let Some(r) = value.as_str() {
                            acc.role = Some(r.to_owned());
                        }
                    }
                    "content" => {
                        if let Some(s) = value.as_str() {
                            acc.content.push_str(s);
                        } else if !value.is_null() {
                            self.unsupported = true;
                        }
                    }
                    // tool_calls / function_call / refusal / reasoning — we can't
                    // losslessly rebuild these from deltas, so don't cache.
                    _ => self.unsupported = true,
                }
            }
        }
        if self.unsupported {
            self.discard();
        }
    }

    fn discard(&mut self) {
        *self = Self {
            unsupported: true,
            ..Self::default()
        };
    }

    /// Rebuild the stored `chat.completion` body, or `None` when the stream
    /// carried unsupported deltas or produced no choices (nothing to cache).
    fn build_body(&self) -> Option<serde_json::Value> {
        use serde_json::json;
        if self.unsupported || self.choices.is_empty() {
            return None;
        }
        let choices: Vec<serde_json::Value> = self
            .choices
            .iter()
            .map(|(index, acc)| {
                json!({
                    "index": index,
                    "message": {
                        "role": acc.role.clone().unwrap_or_else(|| "assistant".to_owned()),
                        "content": acc.content,
                    },
                    "finish_reason": acc.finish_reason.clone().unwrap_or(serde_json::Value::Null),
                })
            })
            .collect();
        let mut body = json!({
            "id": self.id.clone().unwrap_or_default(),
            "object": "chat.completion",
            "model": self.model.clone().unwrap_or_default(),
            "choices": choices,
        });
        if let Some(usage) = &self.usage {
            body["usage"] = usage.clone();
        }
        Some(body)
    }
}

/// Tee-on-miss state: when a streamed call's model opts into caching, the
/// forwarded OpenAI chunks are aggregated into a completion body and stored on
/// clean close. `provider` is the serving route (the §7 failover winner),
/// captured before the base record is consumed by the translator.
pub(super) struct StreamCacheTee {
    pub(super) cache: crate::cache::SharedLlmCache,
    pub(super) canonical: String,
    pub(super) principal_issuer: Option<String>,
    pub(super) ttl: std::time::Duration,
    pub(super) provider: String,
    pub(super) agg: StreamCacheAgg,
}

/// The streaming close-out inputs: the baseline record to fold provider frames
/// into, the usage sink, and the call identity for the ledger row. Bundled so
/// [`finalizing_inference_stream`] keeps a small signature.
pub(super) struct StreamFinalize {
    pub(super) record_base: waygate_llm_translate::InferenceRecord,
    pub(super) usage: Option<crate::usage::SharedLlmUsage>,
    pub(super) tenant_id: String,
    pub(super) principal_sub: Option<String>,
    pub(super) model_alias: String,
    /// Tee-on-miss store, `Some` only when the model opts into caching.
    pub(super) cache_store: Option<StreamCacheTee>,
    /// `true` for a `/v1/responses` caller: forward the provider frames as named
    /// Responses SSE events (passthrough, OpenAI-Responses upstream) rather than
    /// the OpenAI chat-completion-chunk transport. The translator still folds the
    /// audit/usage record; only the client framing differs.
    pub(super) responses_surface: bool,
}

/// Build an OpenAI-chat-shaped `usage` object from a stream's terminal
/// [`InferenceRecord`], for the Responses lifter's terminal event. Anthropic and
/// Gemini fold token usage into the record (not the emitted chat chunks), so this
/// recovers it for `response.completed`/`response.incomplete`. Returns `None` when
/// the record carried no token counts (an unreported class is never fabricated).
fn chat_usage_from_record(
    record: &waygate_llm_translate::InferenceRecord,
) -> Option<serde_json::Value> {
    let u = &record.usage;
    if [u.input, u.output, u.cached_read, u.cache_write, u.reasoning]
        .iter()
        .all(Option::is_none)
    {
        return None;
    }
    let mut m = serde_json::Map::new();
    if let Some(i) = u.input {
        m.insert("prompt_tokens".into(), serde_json::Value::from(i));
    }
    if let Some(o) = u.output {
        m.insert("completion_tokens".into(), serde_json::Value::from(o));
    }
    if let (Some(i), Some(o)) = (u.input, u.output) {
        m.insert("total_tokens".into(), serde_json::Value::from(i + o));
    }
    let mut input_details = serde_json::Map::new();
    if let Some(c) = u.cached_read {
        input_details.insert("cached_tokens".into(), serde_json::Value::from(c));
    }
    if let Some(w) = u.cache_write {
        input_details.insert("cache_write_tokens".into(), serde_json::Value::from(w));
    }
    if !input_details.is_empty() {
        m.insert(
            "prompt_tokens_details".into(),
            serde_json::Value::Object(input_details),
        );
    }
    if let Some(r) = u.reasoning {
        m.insert(
            "completion_tokens_details".into(),
            serde_json::json!({ "reasoning_tokens": r }),
        );
    }
    Some(serde_json::Value::Object(m))
}

/// Wrap a provider SSE frame stream as an [`InvocationStream`], finalizing the
/// outcome audit AND the per-call usage row at stream **close**. The
/// final-outcome stage is deferred to stream close. Each provider `data:`
/// frame is driven through
/// a [`waygate_llm_translate::StreamTranslator`] (chosen from the base record's
/// `upstream_protocol`), which folds it into the `InferenceRecord` and yields
/// the OpenAI client [`InvocationChunk`]s to forward (1:1 for OpenAI; mapped for
/// Anthropic — one event may produce several or none, so they are buffered).
/// `terminal` marks the completion sentinel (the translator's `done`). On
/// completion the best-effort audit row is written and (when a usage sink is
/// wired) the usage row is recorded from the aggregated `InferenceRecord`
/// (tokens / served model / finish reason). The pre-dispatch gates already
/// fired before this stream was built, so authorization/quota are not re-run.
///
/// Usage is recorded only on the success-completion path: provider usage arrives
/// in the terminal frame, so an errored / truncated / client-cancelled stream
/// has no complete metering to ledger — those paths audit the failure but
/// record no usage row.
pub(super) fn finalizing_inference_stream(
    audit: SharedEvidence,
    base_audit: AuditEvent,
    started: std::time::Instant,
    frames: ProviderSseStream,
    fin: StreamFinalize,
) -> InvocationStream {
    use serde_json::Value;
    use std::collections::VecDeque;
    use waygate_llm_translate::StreamTranslator;
    struct State {
        frames: ProviderSseStream,
        audit: SharedEvidence,
        base_audit: AuditEvent,
        started: std::time::Instant,
        finished: bool,
        telemetry_finished: bool,
        // Protocol-aware translator: folds provider frames into the usage record
        // AND maps them to the OpenAI chat-completion-chunk frames the client
        // gets (1:1 for OpenAI, N-for-1 for Anthropic). Chosen from the base
        // record's `upstream_protocol`.
        translator: StreamTranslator,
        // Client frames produced by the current provider frame, not yet yielded.
        // One Anthropic event can produce several (or zero) OpenAI chunks, so the
        // unfold drains this buffer before pulling the next provider frame.
        pending: VecDeque<InvocationChunk>,
        usage: Option<crate::usage::SharedLlmUsage>,
        tenant_id: String,
        principal_sub: Option<String>,
        model_alias: String,
        cache_store: Option<StreamCacheTee>,
        // A `/v1/responses` caller forwards named Responses SSE events instead of
        // chat chunks. Two egresses: an OpenAI-Responses upstream's frames are
        // already Responses events and are passed through 1:1 (R3a,
        // `responses_lifter` is `None`); other upstreams have their normalized chat
        // chunks lifted into Responses events by the lifter (R3b).
        responses_surface: bool,
        responses_lifter: Option<waygate_llm_translate::ChatStreamToResponses>,
    }
    // Client-disconnect safety net: if the consumer (axum SSE egress) drops the
    // stream before reaching a terminal arm — the common SSE early-cancel case —
    // the unfold future is dropped without any inline finalize having run, so
    // Drop records the cancellation outcome out-of-band (Drop is sync, the audit
    // is async, so spawn it). Best-effort: skip if there's no current runtime.
    //
    // Exactly-once invariant: each terminal arm sets `finished = true` only AFTER
    // its `finalize_stream_audit().await` completes, with no await between the
    // two. So either the inline write completed (then `finished` is true → Drop
    // skips) or it did not (then `finished` is false → Drop writes the row). The
    // two are mutually exclusive — a governed call never closes with zero audit
    // rows, and never with two. (A drop *during* an inline finalize loses that
    // arm's specific outcome and is recorded by Drop as a cancellation; the
    // never-zero guarantee is what matters.)
    impl State {
        fn record_failure(&mut self, phase: waygate_telemetry::metrics::LlmFailurePhase) {
            if self.telemetry_finished {
                return;
            }
            self.telemetry_finished = true;
            let record = self.translator.snapshot();
            waygate_telemetry::metrics::record_llm_request_failure(
                record.provider.as_str(),
                &self.model_alias,
                record.provider_account_id.as_deref(),
                self.started.elapsed().as_secs_f64(),
                phase,
            );
        }
    }

    impl Drop for State {
        fn drop(&mut self) {
            self.record_failure(waygate_telemetry::metrics::LlmFailurePhase::Abandoned);
            if self.finished {
                return;
            }
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let audit = self.audit.clone();
                let base = self.base_audit.clone();
                let started = self.started;
                handle.spawn(async move {
                    finalize_stream_audit(
                        &audit,
                        base,
                        AuditOutcome::ExecutionError,
                        Some("stream cancelled by client before completion".to_string()),
                        started,
                    )
                    .await;
                });
            }
        }
    }
    // The lifter is engaged only for a Responses caller routed to a NON-Responses
    // upstream: an OpenAI-Responses upstream's frames are passed through 1:1, so it
    // keeps `None`. Read the protocol before `record_base` moves into the translator.
    let responses_lifter = if fin.responses_surface
        && fin.record_base.upstream_protocol
            != waygate_llm_translate::UpstreamProtocol::OpenAiResponses
    {
        Some(waygate_llm_translate::ChatStreamToResponses::new())
    } else {
        None
    };
    let init = State {
        frames,
        audit,
        base_audit,
        started,
        finished: false,
        telemetry_finished: false,
        translator: StreamTranslator::for_record(fin.record_base),
        pending: VecDeque::new(),
        usage: fin.usage,
        tenant_id: fin.tenant_id,
        principal_sub: fin.principal_sub,
        model_alias: fin.model_alias,
        cache_store: fin.cache_store,
        responses_surface: fin.responses_surface,
        responses_lifter,
    };
    futures::stream::unfold(init, |mut st| async move {
        // Drain client frames buffered from the previous provider frame before
        // pulling the next — one Anthropic event maps to several (or zero) OpenAI
        // chunks. This sits ABOVE the `finished` check so the terminal frame
        // (enqueued by the success path) is still yielded after finalize.
        loop {
            if let Some(chunk) = st.pending.pop_front() {
                return Some((Ok(chunk), st));
            }
            if st.finished {
                return None;
            }
            match st.frames.next().await {
                Some(Ok(ev)) => {
                    // Translate + meter this provider frame. `step.chunks` are the
                    // OpenAI client frames to forward (verbatim for OpenAI; mapped
                    // for Anthropic), folded into the usage record by the same
                    // call; `step.done` marks the logical end (`[DONE]` for OpenAI,
                    // `message_stop` for Anthropic).
                    // Always drive the translator: it folds the audit/usage record
                    // AND detects the logical end (`done`) for both transports.
                    let step = st.translator.push(&ev.data);
                    let done = step.done;
                    // R3b: a Responses caller on a NON-Responses upstream lifts the
                    // normalized chat chunks into Responses events. Anthropic/Gemini
                    // fold usage into the record, not the emitted chat chunks, so derive
                    // a chat-shaped usage fallback from the translator snapshot for the
                    // terminal event — computed before the `&mut` lifter borrow (it
                    // borrows a different field), and only when the lifter is engaged.
                    // The OpenAI-chat usage chunk the lifter already captured wins.
                    let lifter_fallback_usage = if done && st.responses_lifter.is_some() {
                        chat_usage_from_record(&st.translator.snapshot())
                    } else {
                        None
                    };
                    if let Some(lifter) = st.responses_lifter.as_mut() {
                        // On the logical end, `finish()` closes every open item and emits
                        // the terminal `response.completed`/`response.incomplete`.
                        let mut events: Vec<(Option<String>, Value, bool)> = Vec::new();
                        for chunk in &step.chunks {
                            for (name, ev) in lifter.push(chunk) {
                                events.push((Some(name), ev, false));
                            }
                        }
                        if done {
                            let fin = lifter.finish(lifter_fallback_usage);
                            let n = fin.len();
                            for (i, (name, ev)) in fin.into_iter().enumerate() {
                                events.push((Some(name), ev, i + 1 == n));
                            }
                        }
                        for (event_name, event, terminal) in events {
                            st.pending.push_back(InvocationChunk {
                                event,
                                event_name,
                                terminal,
                            });
                        }
                    } else if st.responses_surface {
                        // R3a passthrough: an OpenAI-Responses upstream frame already
                        // IS a Responses event (its `type` is the SSE event name).
                        // Forward it verbatim as a named event — including the
                        // terminal `response.completed`/`response.incomplete` frame
                        // (this transport has no `[DONE]` sentinel). Non-JSON frames
                        // (keepalives) yield nothing. The chat `step.chunks` are
                        // unused here; the audit fold already happened above.
                        if let Ok(event) = serde_json::from_str::<Value>(ev.data.trim()) {
                            let event_name =
                                event.get("type").and_then(Value::as_str).map(str::to_owned);
                            st.pending.push_back(InvocationChunk {
                                event,
                                event_name,
                                terminal: done,
                            });
                        }
                    } else {
                        let chunks = step.chunks;
                        let n = chunks.len();
                        for (i, event) in chunks.into_iter().enumerate() {
                            // Tee-on-miss: fold each forwarded client chunk into the
                            // cache aggregator before it is queued for the client, so
                            // a clean close can rebuild + store the completion.
                            if let Some(tee) = &mut st.cache_store {
                                tee.agg.observe(&event);
                            }
                            // The completion sentinel is the last frame of the done
                            // step; mark it terminal so the SSE egress closes cleanly.
                            let terminal = done && i + 1 == n;
                            st.pending.push_back(InvocationChunk {
                                event,
                                event_name: None,
                                terminal,
                            });
                        }
                    }
                    if done {
                        st.telemetry_finished = true;
                        // Completion signalled — finalize the outcome here, before
                        // the buffered terminal frame is yielded. `finished` is set
                        // only AFTER the audit write completes (see the Drop impl):
                        // a drop while this await is suspended leaves `finished`
                        // false, so the Drop net writes the row instead of it being
                        // lost. No await sits between completion and the assignment,
                        // so the two are mutually exclusive — never zero rows, never
                        // two.
                        finalize_stream_audit(
                            &st.audit,
                            st.base_audit.clone(),
                            AuditOutcome::Success,
                            None,
                            st.started,
                        )
                        .await;
                        st.finished = true;
                        // Persist the per-call usage row from the completed
                        // stream. Runs AFTER `finished` is set so the audit is
                        // already secured — a drop during this best-effort,
                        // separate-sink write can lose only the usage row, never
                        // the audit. Snapshot (not finish) so the translator keeps
                        // living in `st`; shared by the usage row and the cache
                        // store below (both want the served model).
                        let snapshot = st.translator.snapshot();
                        if let Some(sink) = &st.usage {
                            let row = build_usage_row(
                                &snapshot,
                                st.tenant_id.clone(),
                                st.principal_sub.clone(),
                                st.model_alias.clone(),
                                Some(elapsed_ms(st.started)),
                            );
                            sink.record_usage(row).await;
                        }
                        // Tee-on-miss store: rebuild the completion
                        // from the forwarded chunks and cache it. This block is
                        // the ONLY one reached on a clean `[DONE]`, so a truncated
                        // or errored stream never stores. `build_body` returns
                        // `None` when the stream carried deltas we can't faithfully
                        // replay (e.g. tool calls), so we never cache a lossy body.
                        // Best-effort and last, like the usage row.
                        if let Some(tee) = &st.cache_store {
                            if let Some(body) = tee.agg.build_body() {
                                tee.cache
                                    .put(crate::cache::CacheStoreRequest {
                                        canonical_request: tee.canonical.clone(),
                                        tenant_id: st.tenant_id.clone(),
                                        principal_issuer: tee.principal_issuer.clone(),
                                        principal_sub: st.principal_sub.clone(),
                                        model_alias: st.model_alias.clone(),
                                        model_served: snapshot.model_served.clone(),
                                        provider: tee.provider.clone(),
                                        body,
                                        ttl: tee.ttl,
                                    })
                                    .await;
                            }
                        }
                    }
                    // Loop back: yield the first buffered chunk, or — if this frame
                    // produced none (e.g. an Anthropic `ping`) and the stream has
                    // not ended — pull the next provider frame.
                }
                Some(Err(e)) => {
                    st.record_failure(waygate_telemetry::metrics::LlmFailurePhase::Stream);
                    let reason = e.to_string();
                    // Finalize the failure, then mark finished (after the await — a
                    // drop while the audit write is pending leaves `finished` false
                    // so the Drop net still records the outcome; see the Drop impl).
                    finalize_stream_audit(
                        &st.audit,
                        st.base_audit.clone(),
                        AuditOutcome::ExecutionError,
                        Some(reason.clone()),
                        st.started,
                    )
                    .await;
                    st.finished = true;
                    let err = InvocationError::Upstream(ErrorData::internal_error(reason, None));
                    return Some((Err(err), st));
                }
                None => {
                    // The stream terminates with its protocol sentinel (`[DONE]` /
                    // `message_stop`), handled inline in the `Some(Ok(_))` arm
                    // (which sets `finished`; the check above short-circuits before
                    // re-polling). Reaching here means the provider / proxy closed
                    // the connection BEFORE the sentinel — a truncated stream, not a
                    // clean completion.
                    //
                    // Per the InvocationStream contract (a mid-stream failure
                    // surfaces as a terminal error, never a silent truncation),
                    // audit it as a failure and yield a terminal error frame so the
                    // SSE egress emits `event: error` instead of just ending.
                    //
                    // `finished` is set after the audit write (see the Drop impl): a
                    // drop while the write is pending leaves it false so the Drop net
                    // still records the outcome.
                    st.record_failure(waygate_telemetry::metrics::LlmFailurePhase::Stream);
                    let reason =
                        "provider stream closed before the completion sentinel".to_string();
                    finalize_stream_audit(
                        &st.audit,
                        st.base_audit.clone(),
                        AuditOutcome::ExecutionError,
                        Some(reason.clone()),
                        st.started,
                    )
                    .await;
                    st.finished = true;
                    let err = InvocationError::Upstream(ErrorData::internal_error(reason, None));
                    return Some((Err(err), st));
                }
            }
        }
    })
    .boxed()
}

/// Write the close-time chained-best-effort audit row for a streamed LLM call.
async fn finalize_stream_audit(
    audit: &SharedEvidence,
    base: AuditEvent,
    outcome: AuditOutcome,
    reason: Option<String>,
    started: std::time::Instant,
) {
    let event = AuditEvent {
        outcome,
        reason,
        ..base
    }
    .with_latency_ms(elapsed_ms(started));
    audit.record_chained_best_effort(event).await;
}

#[cfg(test)]
mod replay_tests {
    use super::*;
    use futures::StreamExt;
    use serde_json::json;

    /// A cached UNARY tool-call body replayed to a STREAMING client (the cache
    /// key ignores transport) must carry `delta.tool_calls` — not just the
    /// `tool_calls` finish reason — so the client can still execute the call.
    #[tokio::test]
    async fn synthetic_replay_carries_tool_calls() {
        let body = json!({
            "id": "chatcmpl-1", "model": "m",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": null,
                    "tool_calls": [{"id": "c1", "type": "function",
                        "function": {"name": "get_weather", "arguments": "{\"city\":\"SF\"}"}}]},
                "finish_reason": "tool_calls"
            }]
        });
        let chunks: Vec<_> = synthetic_replay_stream(body)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .filter_map(Result::ok)
            .collect();

        // A delta chunk carries the tool call, re-indexed for the stream form.
        let tc = chunks
            .iter()
            .find_map(|c| c.event.pointer("/choices/0/delta/tool_calls/0"))
            .expect("a chunk must carry delta.tool_calls");
        assert_eq!(tc["index"], 0);
        assert_eq!(tc["id"], "c1");
        assert_eq!(tc["function"]["name"], "get_weather");
        assert_eq!(tc["function"]["arguments"], "{\"city\":\"SF\"}");

        // And the finish chunk still carries the tool_calls finish reason.
        assert!(
            chunks.iter().any(|c| c
                .event
                .pointer("/choices/0/finish_reason")
                .and_then(|v| v.as_str())
                == Some("tool_calls")),
            "finish_reason tool_calls must be present"
        );
    }
}

#[cfg(test)]
mod resource_limit_tests {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    #[test]
    fn stream_cache_discards_all_retained_content_at_limit_and_stays_disabled() {
        let mut cache = StreamCacheAgg::default();
        let small = json!({"id":"fixture","choices":[{"index":0,"delta":{"content":"hello"}}]});
        cache.observe(&small);
        assert_eq!(
            cache.build_body().unwrap()["choices"][0]["message"]["content"],
            "hello"
        );
        // Individually permitted chunks can collectively exceed the cache budget.
        let chunk = json!({"choices":[{"index":0,"delta":{"content":"x".repeat(64 * 1024)}}]});
        for _ in 0..17 {
            cache.observe(&chunk);
        }
        assert!(cache.build_body().is_none());
        assert!(cache.choices.is_empty());
        assert!(cache.id.is_none() && cache.model.is_none() && cache.usage.is_none());
        cache.observe(&small);
        assert!(cache.choices.is_empty());
    }

    #[test]
    fn stream_cache_charges_metadata_and_stops_on_unsupported_content() {
        for event in [
            json!({"id":"x".repeat(MAX_STREAM_CACHE_BYTES)}),
            json!({"usage":{"large":"x".repeat(MAX_STREAM_CACHE_BYTES)}}),
            json!({"choices":[{"index":0,"delta":{"tool_calls":[]}}]}),
        ] {
            let mut cache = StreamCacheAgg::default();
            cache.observe(&json!({"choices":[{"index":0,"delta":{"content":"before"}}]}));
            cache.observe(&event);
            assert!(cache.build_body().is_none());
            assert!(cache.choices.is_empty());
        }
    }

    #[tokio::test]
    async fn response_capacity_releases_on_completion_and_cancellation() {
        let capacity = Arc::new(Semaphore::new(1));
        let mut stream = hold_response_capacity(
            Box::pin(futures::stream::empty()),
            capacity.clone().try_acquire_owned().unwrap(),
        );
        assert!(capacity.clone().try_acquire_owned().is_err());
        assert!(stream.next().await.is_none());
        assert_eq!(capacity.available_permits(), 1);
        let pending = hold_response_capacity(
            Box::pin(futures::stream::pending()),
            capacity.clone().try_acquire_owned().unwrap(),
        );
        assert!(capacity.clone().try_acquire_owned().is_err());
        drop(pending);
        assert_eq!(capacity.available_permits(), 1);
    }
}
