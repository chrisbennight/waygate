//! The LLM, embeddings, and images dispatch arm of the pipeline (the dispatch stage for
//! `llm.*` calls), split from `invocation/mod.rs`. Child module of [`super`],
//! the fifteen-stage pipeline.

use super::stream::{
    decision_inputs, finalizing_inference_stream, synthetic_replay_stream, StreamCacheAgg,
    StreamCacheTee, StreamFinalize,
};
use super::*;

mod images;

impl DefaultInvocationService {
    pub(super) async fn invoke_model(
        &self,
        ctx: InvocationContext<'_>,
        model: ResolvedModel,
        dispatcher: &LlmDispatcher,
    ) -> Result<InvocationResponse, InvocationError> {
        // Branch on the model's operation, and reject a surface/operation
        // mismatch with a clean client error BEFORE any gate or cost: an
        // embeddings model must arrive on `/v1/embeddings`, and a chat
        // model on `/v1/chat/completions` or `/v1/responses`. Without this
        // the embeddings parser would choke on a chat body (or vice-versa)
        // or the wrong body would be POSTed to the wrong upstream path.
        if model.operation == LlmOperation::Images || ctx.images_surface.is_some() {
            if model.operation != LlmOperation::Images
                || ctx.images_surface.is_none()
                || ctx.embeddings_surface
                || ctx.responses_surface
            {
                return Err(InvocationError::InvalidArguments(
                    "image models require POST /v1/images/generations or /v1/images/edits".into(),
                ));
            }
            return self.invoke_images(ctx, model, dispatcher).await;
        }
        let is_embeddings_model = model.operation == LlmOperation::Embeddings;
        if is_embeddings_model != ctx.embeddings_surface {
            return Err(InvocationError::InvalidArguments(if is_embeddings_model {
                format!(
                    "model `{}` is an embeddings model; call it on POST /v1/embeddings",
                    ctx.tool
                )
            } else {
                format!(
                    "model `{}` is not an embeddings model; call it on \
                     /v1/chat/completions or /v1/responses",
                    ctx.tool
                )
            }));
        }
        if is_embeddings_model {
            self.invoke_embeddings(ctx, model, dispatcher).await
        } else {
            self.invoke_llm(ctx, model, dispatcher).await
        }
    }
}

/// Scope response content by tenant and issuer-qualified subject. The issuer
/// comes from the authenticated principal, never the inference request.
fn cache_identity(ctx: &InvocationContext<'_>) -> (String, Option<String>, Option<String>) {
    match ctx.principal {
        Some(p) => (
            p.tenant.as_str().to_owned(),
            Some(p.issuer.clone()),
            Some(p.sub.clone()),
        ),
        None => (
            waygate_core::TenantId::default().as_str().to_owned(),
            None,
            None,
        ),
    }
}

/// The cache key's canonical request form: the serialized `LlmRequest` with
/// `stream` normalized to `false`, so the key is transport-agnostic. The cached
/// *content* is identical whether the caller asked for a unary or a streamed
/// response — only the delivery transport differs — so both share one entry: a
/// streaming request can hit a body a unary call stored, and vice versa.
fn cache_canonical(llm_req: &waygate_llm_translate::LlmRequest) -> String {
    let mut keyed = llm_req.clone();
    keyed.stream = false;
    serde_json::to_string(&keyed).unwrap_or_default()
}

/// The cache key's canonical form for an **embeddings** request: the serialized
/// [`EmbeddingsRequest`], with an `embeddings\n` prefix so it can never collide
/// with a chat [`cache_canonical`] key. The two operations already serialize to
/// different JSON shapes, but the explicit prefix makes the separation a
/// guarantee rather than an accident of field naming. Embeddings have no `stream`
/// transport variant, so (unlike chat) there is nothing to normalize.
fn cache_canonical_embeddings(req: &EmbeddingsRequest) -> String {
    format!(
        "embeddings\n{}",
        serde_json::to_string(req).unwrap_or_default()
    )
}

/// The base audit event for an LLM call — principal / tool (server.model) /
/// risk / pii, with a placeholder `Success` outcome and no latency. Callers
/// override `outcome` / `reason` and stamp the latency at the moment the
/// outcome is known (immediately for unary, at stream close for streaming).
fn llm_audit_base(ctx: &InvocationContext<'_>) -> AuditEvent {
    let facts = ctx.facts();
    let (scopes, auth_method, roles, side_effects) = decision_inputs(ctx.principal, facts);
    ctx.audit_event("CallTool", AuditOutcome::Success)
        .with_principal(ctx.principal)
        .with_tool(ctx.server, ctx.tool)
        .with_risk(facts.risk)
        .with_pii(facts.pii)
        // LLM calls audit under their own category so analytics /
        // SIEM routing separate model calls from MCP tool calls. Reads the
        // call's plane from `ctx` (the fast-path set it to `LlmCompletion`
        // before the gates) — one source of truth shared with the gate rows.
        .with_category(ctx.audit_category)
        // Model/LLM calls authorize through the same gate as
        // tool calls and can match Cedar Model permits, so their audit rows
        // record the fired permit ids too — the allow-decision twin of the
        // deny path's `.with_policies`, mirroring the tool-call `record_outcome`
        // / `record_pre_call` rows. Covers every LLM row (success and error)
        // since they all spread `..llm_audit_base(ctx)`. Without this the
        // policy-id reverse lookup would miss successful model decisions.
        .with_policies(ctx.authz_policy_ids.clone())
        // Capture the decision inputs so a recorded model
        // decision can be exactly reconstructed and re-evaluated.
        .with_decision_inputs(scopes, auth_method, roles, side_effects)
}

/// Build a usage-ledger row from a finalized `InferenceRecord` + the call's
/// identity. Shared by the unary record_outcome and the streaming close so both
/// ledger the same shape. Metadata only (I9) — never prompt/completion content.
pub(super) fn build_usage_row(
    record: &waygate_llm_translate::InferenceRecord,
    tenant_id: String,
    principal_sub: Option<String>,
    model_alias: String,
    latency_ms: Option<i64>,
) -> crate::usage::LlmUsageRow {
    let u = &record.usage;
    crate::usage::LlmUsageRow {
        tenant_id,
        principal_sub,
        model_alias,
        provider: record.provider.as_str().to_owned(),
        provider_account_id: record.provider_account_id.clone(),
        model_served: record.model_served.clone(),
        inbound_surface: record.inbound_surface.as_str().to_owned(),
        input_tokens: u.input,
        output_tokens: u.output,
        cached_read_tokens: u.cached_read,
        cache_write_tokens: u.cache_write,
        reasoning_tokens: u.reasoning,
        finish_reason: record.finish_reason.map(|f| f.as_str().to_owned()),
        refusal: record.refusal,
        latency_ms,
        // True only on the cache-hit path (the hit record sets it); every real
        // provider call — unary or streamed — leaves it false.
        gateway_cache_hit: record.gateway_cache_hit,
    }
}

impl DefaultInvocationService {
    /// Dispatch a recognized model through the inference plane,
    /// reusing the shared enforcement gates so an LLM call traverses the same
    /// authorize / quota / approval / audit path as a tool call (invariant I1).
    ///
    /// Synthetic model facts (risk / pii / side-effects) stand in for the
    /// per-model catalog entry — they make the existing gates
    /// fire on the model as a resource. The provider call is the irreversible
    /// step and runs only after every gate has passed (invariant I2).
    pub(super) async fn invoke_llm(
        &self,
        mut ctx: InvocationContext<'_>,
        model: ResolvedModel,
        dispatcher: &LlmDispatcher,
    ) -> Result<InvocationResponse, InvocationError> {
        // Stamp synthetic facts so the shared gates treat the model as a
        // resource (a real model catalog entry replaces these).
        // A synthetic model names no discriminator, so admission has nothing to
        // refuse; the result is still checked rather than dropped.
        ctx.admit_snapshot(crate::catalog::InvocationToolSnapshot::synthetic_model(
            synthetic_model_facts(ctx.server, ctx.tool, model.risk),
        ))?;

        // Input-validation equivalent: translate the payload,
        // rejecting a malformed request BEFORE any cost (no quota, no pre-call
        // row, no provider contact) — mirrors the MCP path.
        let args = ctx.arguments.take().unwrap_or_default();
        let body = serde_json::Value::Object(args);
        // Parse the client surface the call arrived on. The Responses parser sets
        // `LlmRequest::inbound_surface = Responses`, which in turn selects the
        // Responses egress in dispatch (`provider → CanonicalResponse → responses`).
        let mut llm_req = if ctx.responses_surface {
            parse_responses(&body)
        } else {
            parse_chat_completions(&body)
        }
        .map_err(|e| InvocationError::InvalidArguments(e.to_string()))?;
        // Routing and authorization use the catalog tool identity. Keep cache
        // and telemetry metadata on that identity, not caller-supplied text.
        llm_req.model_requested = ctx.tool.to_owned();

        // The input-validation capability gate is still pre-cost: reject a
        // request the resolved route cannot render faithfully — e.g.
        // structured output on a provider with no native equivalent. Return a
        // clean client error before any quota / audit / provider contact (I2),
        // rather than letting it fail
        // deep in dispatch as a transport error (I6). Like the parse error
        // above, this early exit emits no audit row.
        waygate_llm_translate::check_provider_support(&llm_req, model.route.protocol)
            .map_err(|e| InvocationError::InvalidArguments(e.to_string()))?;

        // Every audit row this inference call emits — the gate
        // rejections (denial / step-up / rate-limit / profile), the fail-closed
        // pre-call row, and the completion row — routes to the inference plane,
        // not the MCP tool plane. Set before the shared gates run; they read
        // `ctx.audit_category` (the MCP path leaves it `Invocation`). The only
        // audit-less early exit above is the parse error, which emits no row.
        ctx.audit_category = EvidenceCategory::LlmCompletion;

        // The same gate methods the MCP path runs, in the same order (I1).
        self.extract_facts(&mut ctx).await?;
        // A model authorizes as a distinct Cedar `Model` resource (so the tool
        // step-up, `resource is Tool`, never double-gates it), built from the
        // shared `extract_facts` PIP facts. Models are NOT step-up-gated: model
        // access is an authorization concern (a Cedar permit on a group), not a
        // freshness one. Clear the tool-derived `required_scope` that
        // `build_call_facts` stamped from the risk tier — a Model carries none
        // (see docs/authorization-model.md §6). Only present when a
        // principal is set (anonymous/disabled-auth calls skip the gate).
        if let Some(facts) = ctx.pip_facts.as_mut() {
            facts.resource.resource_type = Some(waygate_core::MODEL_RESOURCE_TYPE.to_owned());
            facts.action.required_scope = None;
        }
        self.authorize(&mut ctx).await?;
        self.check_profile_restrictions(&mut ctx).await?;
        self.prepare_output_validation(&mut ctx).await?;
        self.check_quota(&mut ctx).await?;
        // Lagging token/cost budget (LLM-specific, after the shared
        // request-rate quota). Before record_pre_call + dispatch (I2).
        self.check_llm_budget(&ctx).await?;
        self.check_approval(&mut ctx).await?;
        self.record_pre_call(&mut ctx).await?;

        let started = std::time::Instant::now();

        // Per-principal cache check (opt-in via the model's cache TTL).
        // A hit replays the stored response for free — no provider call, so it is
        // never charged tokens. The lookup runs only AFTER every gate passed
        // (authorize / budget / approval), so a hit is a governed call that
        // simply cost nothing. The key is per-principal, so a hit can only ever
        // replay THIS principal's own prior completion. The key is also
        // transport-agnostic (it ignores `stream`), so the cached *content* is
        // shared across transports: a streaming request can hit a body stored by
        // a unary call (and vice versa), served in whichever transport the
        // current request asked for.
        if let (Some(cache), Some(_ttl)) = (&self.llm_cache, model.cache_ttl) {
            let canonical = cache_canonical(&llm_req);
            let (tenant_id, principal_issuer, principal_sub) = cache_identity(&ctx);
            // R3a: the streaming cache replay (`synthetic_replay_stream`) is
            // chat-shaped, so a streaming Responses request dispatches live rather
            // than be served a mis-shaped replay (a responses-shaped replay is a
            // follow-up). The cache key is surface-aware, so unary Responses hits
            // are served verbatim and stay cached.
            let hit = if ctx.responses_surface && llm_req.stream {
                None
            } else {
                cache
                    .get(
                        &canonical,
                        &tenant_id,
                        principal_issuer.as_deref(),
                        principal_sub.as_deref(),
                    )
                    .await
            };
            if let Some(hit) = hit {
                ctx.latency_ms = Some(elapsed_ms(started));
                self.record_llm_outcome(&ctx, AuditOutcome::Success, None)
                    .await;
                // Emit an InferenceRecord flagged as a cache hit (free: no
                // provider tokens). Attribute it to the provider that actually
                // served the original miss — a §7 failover may have used a
                // fallback, so the model's *current* primary can differ —
                // falling back to the current primary for a legacy entry with no
                // stored provider. model_served likewise carries the
                // originally-served model so the durable usage row and gen_ai.*
                // metrics attribute the hit correctly. A streaming hit is
                // finalized here, synchronously: the full body is already known,
                // so unlike a live stream there is nothing to defer to close —
                // the returned stream is a pure replay that does no auditing.
                let served_provider = hit
                    .provider
                    .as_deref()
                    .and_then(waygate_llm_credentials::LlmProvider::from_canonical_str)
                    .unwrap_or(model.route.provider);
                let mut record = waygate_llm_translate::InferenceRecord::new(
                    served_provider,
                    &model.route.credential_label,
                    ctx.tool,
                    llm_req.inbound_surface,
                    model.route.protocol,
                );
                record.model_served = hit.model_served;
                record.gateway_cache_hit = true;
                self.record_llm_usage(&ctx, &record).await;
                // Deliver in the transport the current request asked for: a
                // streamed request gets the stored body re-emitted as a synthetic
                // OpenAI SSE chunk stream; a unary request gets it verbatim.
                if llm_req.stream {
                    return Ok(InvocationResponse::Stream(synthetic_replay_stream(
                        hit.body,
                    )));
                }
                return Ok(InvocationResponse::UnaryValue(hit.body));
            }
        }

        // Irreversible provider call — only after every gate passed (I2) and the
        // cache missed. Fails over across the model's credential pool (§7) on a
        // retryable initial failure; a single-credential model has no fallbacks.
        let result = dispatcher
            .dispatch_with_failover(&llm_req, &model.route, &model.fallbacks, model.ttfb)
            .await;

        match result {
            Ok(DispatchOutcome::Unary { record, body }) => {
                ctx.latency_ms = Some(elapsed_ms(started));
                // Basic audit row first (activity feed), then the per-call
                // usage ledger row built from the InferenceRecord.
                // The budget debit reads this ledger.
                self.record_llm_outcome(&ctx, AuditOutcome::Success, None)
                    .await;
                self.record_llm_usage(&ctx, &record).await;
                // Store the completion (opt-in via the model's cache
                // TTL) under the transport-agnostic key so a future identical
                // request from THIS principal — unary OR streaming — is served
                // from cache. This arm is only ever reached by a unary dispatch;
                // storing a streamed completion (tee-on-miss) is a follow-up.
                // Best-effort — a cache write never fails the response just
                // produced.
                if let (Some(cache), Some(ttl)) = (&self.llm_cache, model.cache_ttl) {
                    if !llm_req.stream {
                        let (tenant_id, principal_issuer, principal_sub) = cache_identity(&ctx);
                        cache
                            .put(crate::cache::CacheStoreRequest {
                                canonical_request: cache_canonical(&llm_req),
                                tenant_id,
                                principal_issuer,
                                principal_sub,
                                model_alias: ctx.tool.to_owned(),
                                model_served: record.model_served.clone(),
                                // The provider that actually served this miss
                                // (the failover winner), so a later hit
                                // attributes to it rather than the current
                                // primary.
                                provider: record.provider.as_str().to_owned(),
                                body: body.clone(),
                                ttl,
                            })
                            .await;
                    }
                }
                Ok(InvocationResponse::UnaryValue(body))
            }
            Ok(DispatchOutcome::Stream {
                record_base,
                frames,
            }) => {
                // The pre-dispatch gates already fired (I1). The outcome audit
                // is finalized by the final-outcome stage at stream CLOSE,
                // inside the returned stream. `invoke` returns before the
                // stream is consumed by the egress. Build the audit base eagerly
                // here while `ctx` is borrowable; the stream must be `'static`.
                //
                // `record_base` seeds the streaming usage aggregator:
                // provider frames fold into it and the per-call usage row is
                // recorded at `[DONE]`. Capture the call identity now (the
                // stream is `'static`, so it can't borrow `ctx` at close).
                let base_audit = llm_audit_base(&ctx);
                let (tenant_id, principal_sub) = match ctx.principal {
                    Some(p) => (p.tenant.as_str().to_owned(), Some(p.sub.clone())),
                    None => (waygate_core::TenantId::default().as_str().to_owned(), None),
                };
                // Tee-on-miss: when this model opts into caching, the
                // stream's forwarded chunks are aggregated and stored on clean
                // close. Capture the serving provider (the §7 failover winner)
                // here, before `record_base` is moved into the translator.
                // The tee aggregator rebuilds an OpenAI chat body from the
                // forwarded chunks, so it only applies to the chat transport. A
                // Responses caller forwards named events (not chat chunks), so it
                // skips the tee — a responses-shaped streaming cache is a follow-up.
                let cache_store = match (&self.llm_cache, model.cache_ttl) {
                    (Some(cache), Some(ttl)) if !ctx.responses_surface => Some(StreamCacheTee {
                        cache: cache.clone(),
                        canonical: cache_canonical(&llm_req),
                        principal_issuer: ctx.principal.map(|p| p.issuer.clone()),
                        ttl,
                        provider: record_base.provider.as_str().to_owned(),
                        agg: StreamCacheAgg::default(),
                    }),
                    _ => None,
                };
                let responses_surface = ctx.responses_surface;
                let stream = finalizing_inference_stream(
                    self.audit.clone(),
                    base_audit,
                    started,
                    frames,
                    StreamFinalize {
                        record_base,
                        usage: self.llm_usage.clone(),
                        tenant_id,
                        principal_sub,
                        model_alias: ctx.tool.to_owned(),
                        cache_store,
                        responses_surface,
                    },
                );
                Ok(InvocationResponse::Stream(stream))
            }
            Err(e) => {
                let reason = e.to_string();
                let err =
                    InvocationError::Upstream(ErrorData::internal_error(reason.clone(), None));
                ctx.latency_ms = Some(elapsed_ms(started));
                self.record_llm_outcome(&ctx, AuditOutcome::ExecutionError, Some(reason))
                    .await;
                Err(err)
            }
        }
    }

    /// Dispatch a recognized **embeddings** model through the inference plane.
    /// The chat-path sibling of [`invoke_llm`](Self::invoke_llm): it reuses the
    /// SAME enforcement gates (authorize / profile / quota / budget / approval /
    /// pre-call) so an embeddings call is governed exactly like a chat call and a
    /// tool call (invariant I1), and the irreversible provider call runs only
    /// after every gate has passed (I2). Embeddings are unary-only, so there is
    /// no streaming egress; the per-principal exact-match cache (§9) applies on
    /// the same opt-in arming as chat (a hit replays the stored body verbatim,
    /// free — no provider call).
    pub(super) async fn invoke_embeddings(
        &self,
        mut ctx: InvocationContext<'_>,
        model: ResolvedModel,
        dispatcher: &LlmDispatcher,
    ) -> Result<InvocationResponse, InvocationError> {
        // Synthetic model facts so the shared gates treat the model as a
        // resource (a real catalog entry replaces these).
        // A synthetic model names no discriminator, so admission has nothing to
        // refuse; the result is still checked rather than dropped.
        ctx.admit_snapshot(crate::catalog::InvocationToolSnapshot::synthetic_model(
            synthetic_model_facts(ctx.server, ctx.tool, model.risk),
        ))?;

        // Input-validation equivalent: translate the embeddings
        // payload, rejecting a malformed request BEFORE any cost (no quota, no
        // pre-call row, no provider contact) — mirrors the chat path. This early
        // exit emits no audit row.
        let args = ctx.arguments.take().unwrap_or_default();
        let body = serde_json::Value::Object(args);
        let emb_req = parse_embeddings(&body)
            .map_err(|e| InvocationError::InvalidArguments(e.to_string()))?;

        // Every audit row this inference call emits routes to the inference plane.
        ctx.audit_category = EvidenceCategory::LlmCompletion;

        // The same gate methods the chat/MCP paths run, in the same order (I1).
        self.extract_facts(&mut ctx).await?;
        // A model authorizes as a distinct Cedar `Model` resource (so the tool
        // step-up never double-gates it); models are not step-up-gated, so clear
        // the tool-derived required_scope. Only present when a principal is set.
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

        // Per-principal cache check (opt-in via the model's cache TTL), after
        // every gate passed (authorize / budget / approval) — a hit is a governed
        // call that simply cost nothing. The key is per-principal, so a hit only
        // ever replays THIS principal's own prior result. Embeddings are unary, so
        // this is the simplest cache path: no streaming tee/replay, just a verbatim
        // body served back.
        if let (Some(cache), Some(_ttl)) = (&self.llm_cache, model.cache_ttl) {
            let canonical = cache_canonical_embeddings(&emb_req);
            let (tenant_id, principal_issuer, principal_sub) = cache_identity(&ctx);
            if let Some(hit) = cache
                .get(
                    &canonical,
                    &tenant_id,
                    principal_issuer.as_deref(),
                    principal_sub.as_deref(),
                )
                .await
            {
                ctx.latency_ms = Some(elapsed_ms(started));
                self.record_llm_outcome(&ctx, AuditOutcome::Success, None)
                    .await;
                // Free hit (no provider tokens). Attribute it to the provider that
                // served the original miss — a §7 failover may have used a fallback
                // — falling back to the current primary for a legacy entry with no
                // stored provider. `Surface::Embeddings` + the route's (inert)
                // protocol mirror the live dispatch record.
                let served_provider = hit
                    .provider
                    .as_deref()
                    .and_then(waygate_llm_credentials::LlmProvider::from_canonical_str)
                    .unwrap_or(model.route.provider);
                let mut record = waygate_llm_translate::InferenceRecord::new(
                    served_provider,
                    &model.route.credential_label,
                    ctx.tool,
                    waygate_llm_translate::Surface::Embeddings,
                    model.route.protocol,
                );
                record.model_served = hit.model_served;
                record.gateway_cache_hit = true;
                self.record_llm_usage(&ctx, &record).await;
                return Ok(InvocationResponse::UnaryValue(hit.body));
            }
        }

        // Irreversible provider call — only after every gate passed (I2) and the
        // cache missed. Fails over across the model's credential pool (§7) on a
        // retryable failure.
        let result = dispatcher
            .dispatch_embeddings_with_failover(&emb_req, &model.route, &model.fallbacks)
            .await;

        match result {
            Ok((record, body)) => {
                ctx.latency_ms = Some(elapsed_ms(started));
                // Activity-feed audit row, then the per-call usage ledger row
                // (input-token usage only — the budget debit reads this ledger).
                self.record_llm_outcome(&ctx, AuditOutcome::Success, None)
                    .await;
                self.record_llm_usage(&ctx, &record).await;
                // Store the result (opt-in via the model's cache TTL) under the
                // per-principal key so a future identical request from THIS
                // principal is served from cache. Best-effort — a cache write
                // never fails the response just produced. The provider recorded is
                // the §7 failover winner, so a later hit attributes to it.
                if let (Some(cache), Some(ttl)) = (&self.llm_cache, model.cache_ttl) {
                    let (tenant_id, principal_issuer, principal_sub) = cache_identity(&ctx);
                    cache
                        .put(crate::cache::CacheStoreRequest {
                            canonical_request: cache_canonical_embeddings(&emb_req),
                            tenant_id,
                            principal_issuer,
                            principal_sub,
                            model_alias: ctx.tool.to_owned(),
                            model_served: record.model_served.clone(),
                            provider: record.provider.as_str().to_owned(),
                            body: body.clone(),
                            ttl,
                        })
                        .await;
                }
                Ok(InvocationResponse::UnaryValue(body))
            }
            Err(e) => {
                let status = e.provider_status().unwrap_or(502);
                let reason = format!("embedding backend request failed ({status})");
                let err = InvocationError::Upstream(ErrorData::internal_error(
                    reason.clone(),
                    Some(serde_json::json!({
                        "embedding_http_status": status,
                        "retry_after_seconds": e.provider_retry_after_seconds(),
                    })),
                ));
                ctx.latency_ms = Some(elapsed_ms(started));
                self.record_llm_outcome(&ctx, AuditOutcome::ExecutionError, Some(reason))
                    .await;
                Err(err)
            }
        }
    }

    /// Chained-best-effort audit row for an LLM dispatch outcome. Mirrors the
    /// success / execution-error arms of `record_outcome` (the
    /// deny/quota/approval rows are already emitted by their gates, so this
    /// only covers post-dispatch outcomes).
    async fn record_llm_outcome(
        &self,
        ctx: &InvocationContext<'_>,
        outcome: AuditOutcome,
        reason: Option<String>,
    ) {
        let event = AuditEvent {
            outcome,
            reason,
            ..llm_audit_base(ctx)
        }
        .with_latency_ms(ctx.latency_ms.unwrap_or(0));
        self.audit.record_chained_best_effort(event).await;
    }

    /// Persist a per-call usage row built from the call's
    /// `InferenceRecord`. No-op when no usage sink is wired (DB-less
    /// deployments). Best-effort — the sink logs and drops on error rather
    /// than fail the already-served response. Identity (tenant / principal)
    /// mirrors the audit row so the budget gate can attribute budgets to the same
    /// principal; anonymous (auth-disabled) calls record a `None` principal
    /// under the default tenant. Carries metadata only (I9) — never content.
    async fn record_llm_usage(
        &self,
        ctx: &InvocationContext<'_>,
        record: &waygate_llm_translate::InferenceRecord,
    ) {
        let Some(sink) = &self.llm_usage else {
            return;
        };
        let (tenant_id, principal_sub) = match ctx.principal {
            Some(p) => (p.tenant.as_str().to_owned(), Some(p.sub.clone())),
            None => (waygate_core::TenantId::default().as_str().to_owned(), None),
        };
        let row = build_usage_row(
            record,
            tenant_id,
            principal_sub,
            ctx.tool.to_owned(),
            ctx.latency_ms,
        );
        sink.record_usage(row).await;
    }

    /// The lagging LLM budget gate (I3). No-op when no budget gate
    /// is wired. Refuses the call — BEFORE the irreversible provider dispatch
    /// (I2) — when the principal is already at/over an applicable token/cost
    /// budget, recording a `Denied` audit row. Anonymous (auth-disabled) calls
    /// carry `None` principal, so only tenant-wide budgets apply to them.
    async fn check_llm_budget(&self, ctx: &InvocationContext<'_>) -> Result<(), InvocationError> {
        let Some(gate) = &self.llm_budget else {
            return Ok(());
        };
        let (tenant_id, principal_sub) = match ctx.principal {
            Some(p) => (p.tenant.as_str().to_owned(), Some(p.sub.clone())),
            None => (waygate_core::TenantId::default().as_str().to_owned(), None),
        };
        if let Some(rej) = gate
            .check(&tenant_id, principal_sub.as_deref(), ctx.tool)
            .await
        {
            let event = AuditEvent {
                outcome: AuditOutcome::Denied,
                reason: Some(format!(
                    "llm budget exhausted ({}): {}",
                    rej.dimension, rej.reason
                )),
                ..llm_audit_base(ctx)
            };
            self.audit.record_chained_best_effort(event).await;
            return Err(InvocationError::BudgetExceeded {
                dimension: rej.dimension,
                reason: rej.reason,
            });
        }
        Ok(())
    }
}
