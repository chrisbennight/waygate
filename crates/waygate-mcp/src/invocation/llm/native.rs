//! The provider-native Anthropic Messages arm. The request body is validated
//! and forwarded without canonical translation, so provider features the
//! canonical model does not represent (prompt-cache breakpoints, extended
//! thinking, server-side tools, native content blocks) reach the provider
//! intact. Every governance stage of the canonical arm still applies.

use super::*;
use waygate_llm_dispatch::NativeMessagesRequest;

/// Shape checks that need no provider contact. The provider validates the
/// rest of the body; these keep the gateway's own decisions (transport and
/// routing) from depending on malformed input.
fn parse_native_messages(
    model_requested: &str,
    body: serde_json::Map<String, serde_json::Value>,
) -> Result<NativeMessagesRequest, InvocationError> {
    let stream = match body.get("stream") {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::Bool(stream)) => *stream,
        Some(_) => {
            return Err(InvocationError::InvalidArguments(
                "`stream` must be a boolean".into(),
            ))
        }
    };
    if !body
        .get("messages")
        .is_some_and(serde_json::Value::is_array)
    {
        return Err(InvocationError::InvalidArguments(
            "missing required array field `messages`".into(),
        ));
    }
    if !body
        .get("max_tokens")
        .and_then(serde_json::Value::as_u64)
        .is_some_and(|n| n > 0)
    {
        return Err(InvocationError::InvalidArguments(
            "missing required positive integer field `max_tokens`".into(),
        ));
    }
    Ok(NativeMessagesRequest {
        model_requested: model_requested.to_owned(),
        body,
        stream,
    })
}

impl DefaultInvocationService {
    /// Dispatch a chat model on the native Messages surface through the same
    /// authorize / profile / quota / budget / approval / audit stages as the
    /// canonical arm (I1), with the provider call last (I2). The model must be
    /// served by an Anthropic Messages route; fallbacks on any other protocol
    /// are skipped because the native body has no rendering for them. Native
    /// requests bypass the gateway exact-match cache, whose key is the
    /// canonical request.
    pub(in crate::invocation) async fn invoke_native_messages(
        &self,
        mut ctx: InvocationContext<'_>,
        model: ResolvedModel,
        dispatcher: &LlmDispatcher,
    ) -> Result<InvocationResponse, InvocationError> {
        ctx.admit_snapshot(crate::catalog::InvocationToolSnapshot::synthetic_model(
            synthetic_model_facts(ctx.server, ctx.tool, model.risk),
        ))?;
        if model.route.protocol != waygate_llm_translate::UpstreamProtocol::AnthropicMessages {
            return Err(InvocationError::InvalidArguments(format!(
                "model `{}` is not served by an Anthropic Messages route; call it on \
                 /v1/chat/completions or /v1/responses",
                ctx.tool
            )));
        }
        let fallbacks: Vec<_> = model
            .fallbacks
            .iter()
            .filter(|route| {
                route.protocol == waygate_llm_translate::UpstreamProtocol::AnthropicMessages
            })
            .cloned()
            .collect();
        let request = parse_native_messages(ctx.tool, ctx.arguments.take().unwrap_or_default())?;

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
        let response_capacity = self.admit_llm_response(&ctx, dispatcher).await?;
        self.record_pre_call(&mut ctx).await?;

        let started = std::time::Instant::now();
        let result = dispatcher
            .dispatch_native_messages_with_failover(&request, &model.route, &fallbacks, model.ttfb)
            .await;

        match result {
            Ok(DispatchOutcome::Unary { record, body }) => {
                ctx.latency_ms = Some(elapsed_ms(started));
                self.record_llm_outcome(&ctx, AuditOutcome::Success, None)
                    .await;
                self.record_llm_usage(&ctx, &record).await;
                Ok(InvocationResponse::UnaryValue(body))
            }
            Ok(DispatchOutcome::Stream {
                record_base,
                frames,
            }) => {
                let base_audit = llm_audit_base(&ctx);
                let (tenant_id, principal_sub) = match ctx.principal {
                    Some(p) => (p.tenant.as_str().to_owned(), Some(p.sub.clone())),
                    None => (waygate_core::TenantId::default().as_str().to_owned(), None),
                };
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
                        cache_store: None,
                        framing: ClientFraming::NativeRelay,
                    },
                );
                Ok(InvocationResponse::Stream(hold_response_capacity(
                    stream,
                    response_capacity,
                )))
            }
            Err(e) => {
                let reason = e.to_string();
                ctx.latency_ms = Some(elapsed_ms(started));
                self.record_llm_outcome(&ctx, AuditOutcome::ExecutionError, Some(reason.clone()))
                    .await;
                Err(InvocationError::Upstream(ErrorData::internal_error(
                    reason, None,
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_native_messages;
    use serde_json::{json, Map, Value};

    fn body(v: Value) -> Map<String, Value> {
        v.as_object().cloned().expect("object")
    }

    #[test]
    fn native_body_is_kept_verbatim_including_provider_only_fields() {
        let original = body(json!({
            "model": "alias",
            "max_tokens": 64,
            "stream": true,
            "system": [{"type": "text", "text": "s", "cache_control": {"type": "ephemeral"}}],
            "messages": [{"role": "user", "content": "hi"}],
            "thinking": {"type": "enabled", "budget_tokens": 1024}
        }));
        let parsed = parse_native_messages("alias", original.clone()).expect("valid");
        assert!(parsed.stream);
        assert_eq!(parsed.model_requested, "alias");
        assert_eq!(parsed.body, original);
    }

    #[test]
    fn native_body_rejects_shapes_the_gateway_relies_on() {
        let ok = json!({"model": "m", "max_tokens": 1, "messages": []});
        assert!(!parse_native_messages("m", body(ok.clone())).unwrap().stream);
        for (field, bad) in [
            ("stream", json!("yes")),
            ("messages", json!("hi")),
            ("max_tokens", json!(0)),
            ("max_tokens", json!(-1)),
            ("max_tokens", json!("64")),
        ] {
            let mut b = body(ok.clone());
            b.insert(field.to_owned(), bad.clone());
            assert!(
                parse_native_messages("m", b).is_err(),
                "{field}={bad} must be rejected"
            );
        }
        for field in ["messages", "max_tokens"] {
            let mut b = body(ok.clone());
            b.remove(field);
            assert!(
                parse_native_messages("m", b).is_err(),
                "{field} is required"
            );
        }
    }
}
