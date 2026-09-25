use super::*;

impl DefaultInvocationService {
    #[must_use]
    pub fn with_file_input_processor(
        mut self,
        processor: Option<crate::files::SharedFileInputProcessor>,
    ) -> Self {
        self.file_input_processor = processor;
        self
    }

    /// Wire the key that seals this gateway's MRTR continuation state.
    /// Without it, pauses relay verbatim and elicited files are refused.
    #[must_use]
    pub fn with_continuation_sealer(
        mut self,
        sealer: Option<std::sync::Arc<super::continuation::ContinuationSealer>>,
    ) -> Self {
        self.continuation_sealer = sealer;
        self
    }

    #[must_use]
    pub fn with_file_output_processor(
        mut self,
        processor: Option<crate::files::SharedFileOutputProcessor>,
    ) -> Self {
        self.file_output_processor = processor;
        self
    }

    /// Deterministic file-input admission (transfer-mode and inline-content
    /// constraints), run before quota and the one-time approval claim so a
    /// refusal cannot burn a consumable resource the caller cannot get back.
    /// Delivery — which moves bytes and takes authority — stays in
    /// `prepare_and_validate_file_inputs` after those gates. A refusal is a
    /// policy denial and records the same best-effort evidence as the
    /// pipeline's other pre-dispatch refusals.
    pub(super) async fn admit_file_inputs(
        &self,
        ctx: &mut InvocationContext<'_>,
    ) -> Result<(), InvocationError> {
        let Some(processor) = self.file_input_processor.as_ref() else {
            return Ok(());
        };
        // The schema clone is schema-sized and taken only for tools that
        // actually declare file inputs; the payload-sized argument map is
        // moved through admission, never copied, and the compiled validator
        // from `validate_input` is reused instead of recompiled. An MRTR
        // continuation payload is admitted alongside the arguments even for
        // tools without declared file inputs, so a deliverability refusal
        // still precedes the quota and approval gates.
        let has_continuation = ctx.mrtr.input_responses.is_some();
        let schema = match ctx.tool_snapshot().input_schema() {
            Some(schema) if crate::files::schema_declares_file_inputs(schema) => {
                Some(schema.clone())
            }
            _ if has_continuation => None,
            _ => return Ok(()),
        };
        let compiled = ctx.compiled_input_validator.clone();
        if let Err(error) = processor.admit(
            schema.as_ref(),
            compiled.as_deref(),
            &mut ctx.arguments,
            ctx.mrtr.input_responses.as_ref(),
            ctx.continuation
                .deliverable_keys
                .as_deref()
                .unwrap_or_default(),
        ) {
            self.record_file_admission_refusal(ctx, &error).await;
            return Err(InvocationError::Upstream(error));
        }
        Ok(())
    }

    async fn record_file_admission_refusal(
        &self,
        ctx: &InvocationContext<'_>,
        error: &rmcp::ErrorData,
    ) {
        // Carries the same classification fields as the pipeline's other
        // classified CallTool denials so risk- and PII-filtered audit
        // monitoring sees a refused attempt against a classified tool. The
        // reason records the refusal's own caller-facing message: a mode or
        // content denial, an undeliverable reference on a storage-disabled
        // gateway, and an invalid annotation are distinct causes and must
        // stay distinguishable in the durable evidence.
        let facts = ctx.facts();
        self.audit
            .record_chained_best_effort(
                ctx.audit_event("CallTool", AuditOutcome::Denied)
                    .with_category(ctx.audit_category)
                    .with_principal(ctx.principal)
                    .with_tool(ctx.server, ctx.tool)
                    .with_risk(facts.risk)
                    .with_pii(facts.pii)
                    .with_reason(format!(
                        "file input refused before dispatch: {}",
                        error.message
                    )),
            )
            .await;
    }

    pub(super) async fn prepare_and_validate_file_inputs(
        &self,
        ctx: &mut InvocationContext<'_>,
    ) -> Result<(), InvocationError> {
        let Some(processor) = self.file_input_processor.as_ref() else {
            return Ok(());
        };
        let schema = ctx.tool_snapshot().input_schema().cloned();
        let rewritten = processor
            .prepare(
                crate::files::FileInputContext {
                    principal: ctx.principal.cloned(),
                    server: ctx.server.to_owned(),
                    tool: ctx.tool.to_owned(),
                    invocation_id: ctx.invocation_id.to_string(),
                    admitted_contract: ctx.tool_snapshot().contract_identity(),
                    compiled_input_schema: ctx.compiled_input_validator.clone(),
                },
                schema.as_ref(),
                &mut ctx.arguments,
            )
            .await
            .map_err(InvocationError::Upstream)?;
        if rewritten {
            self.validate_input(ctx).await?;
        }
        // Elicited files inside an MRTR continuation follow the same
        // delivery pipeline before the retry is dispatched: caller-owned
        // gateway references are delivered to the selected upstream and
        // replaced with its private references, so the upstream receives a
        // continuation it can resolve. The responses are caller-authored
        // values for the upstream's own elicitation; they are not validated
        // against the tool's input schema. Delivery runs only under keys a
        // verified continuation says this pause opened by elicitation — the
        // envelope carries the upstream's own request shape, so the
        // destination is never taken from the caller.
        let file_keys = ctx
            .continuation
            .deliverable_keys
            .clone()
            .unwrap_or_default();
        if !file_keys.is_empty() && ctx.mrtr.input_responses.is_some() {
            let continuation_context = crate::files::FileInputContext {
                principal: ctx.principal.cloned(),
                server: ctx.server.to_owned(),
                tool: ctx.tool.to_owned(),
                invocation_id: ctx.invocation_id.to_string(),
                admitted_contract: ctx.tool_snapshot().contract_identity(),
                compiled_input_schema: ctx.compiled_input_validator.clone(),
            };
            if let Some(input_responses) = ctx.mrtr.input_responses.as_mut() {
                processor
                    .prepare_continuation(continuation_context, input_responses, &file_keys)
                    .await
                    .map_err(InvocationError::Upstream)?;
            }
        }
        Ok(())
    }

    pub(super) async fn prepare_files_and_validate_output(
        &self,
        ctx: &mut InvocationContext<'_>,
        mut result: Result<CallToolResult, InvocationError>,
    ) -> Result<Result<CallToolResult, InvocationError>, InvocationError> {
        let mut prepared_batch = None;
        let recovered = ctx
            .retained_response
            .lock()
            .expect("retained response lock")
            .take();
        let retained = recovered.is_some()
            || ctx
                .retained_operation_succeeded
                .load(std::sync::atomic::Ordering::Relaxed);
        let retained_file_delivery = recovered.as_ref().is_some_and(|body| body.file_delivery);
        if retained_file_delivery {
            // Validate the inspected body before compaction replaces it with
            // a gateway file reference. That reference is not upstream data.
            if let Err(error) = self.validate_output(ctx, &result).await {
                ctx.pending_redactions.clear();
                return if ctx.facts().side_effects {
                    Ok(Ok(super::retained_response::delivery_failure(
                        CallToolResult::success(Vec::new()),
                        error.kind(),
                    )))
                } else {
                    Err(error)
                };
            }
        }
        self.enter_stage(InvocationStage::PrepareFileOutputs);
        if let Some(recovered) = recovered {
            match result {
                Ok(output) if recovered.file_delivery => {
                    let body = recovered.inspected_bytes(&output);
                    let byte_count = body.as_ref().map_or(0, Vec::len);
                    let sensitive =
                        super::result_trust::parse(&output).is_ok_and(|trust| trust.sensitive);
                    let mut compact = recovered.compact(output);
                    let staged = match (self.file_output_processor.as_ref(), body) {
                        (Some(processor), Ok(bytes)) => processor
                            .prepare_retained(
                                crate::files::FileOutputContext {
                                    principal: ctx.principal.cloned(),
                                    server: ctx.server.to_owned(),
                                    tool: ctx.tool.to_owned(),
                                    invocation_id: ctx.invocation_id.to_string(),
                                },
                                crate::files::RetainedFileBody {
                                    upstream_uri: recovered.target.uri.clone(),
                                    media_type: recovered.target.media_type.clone(),
                                    bytes,
                                    sensitive,
                                },
                            )
                            .await
                            .map_err(InvocationError::Upstream),
                        (_, Err(error)) => Err(error),
                        (None, _) => {
                            Err(InvocationError::Upstream(rmcp::ErrorData::internal_error(
                                "retained response file storage is unavailable",
                                None,
                            )))
                        }
                    };
                    result = match staged {
                        Ok(prepared) => {
                            if let Some(root) = compact.structured_content.as_mut() {
                                root["payload"]["bytes"] = serde_json::json!(byte_count);
                                compact.content =
                                    vec![rmcp::model::ContentBlock::text(root.to_string())];
                            }
                            crate::retained_delivery::attach(
                                &mut compact,
                                crate::retained_delivery::Delivery::File {
                                    operation_status:
                                        crate::retained_delivery::OperationStatus::Succeeded,
                                    file: prepared.file.clone(),
                                },
                            );
                            compact
                                .content
                                .push(rmcp::model::ContentBlock::resource_link(
                                    rmcp::model::Resource::new(
                                        prepared.file.uri.clone(),
                                        "Complete connector response",
                                    )
                                    .with_mime_type(recovered.target.media_type.clone()),
                                ));
                            prepared_batch = Some((prepared.batch_id, 1));
                            Ok(compact)
                        }
                        Err(_) if ctx.facts().side_effects => {
                            ctx.pending_redactions.clear();
                            Ok(super::retained_response::delivery_failure(
                                compact,
                                "retained_response_staging_failed",
                            ))
                        }
                        Err(error) => Err(error),
                    };
                }
                Ok(output) => {
                    result = Ok(output);
                }
                Err(error) if ctx.facts().side_effects => {
                    // Inspection refused delivery after dispatch. Preserve the
                    // applied outcome without forwarding any rejected content.
                    ctx.pending_redactions.clear();
                    result = Ok(super::retained_response::delivery_failure(
                        CallToolResult::success(Vec::new()),
                        error.kind(),
                    ));
                }
                Err(error) => {
                    result = Err(error);
                }
            }
        }
        if let Some(processor) = self
            .file_output_processor
            .as_ref()
            .filter(|_| !retained_file_delivery)
        {
            result = match result {
                Ok(output) => match processor
                    .prepare(
                        crate::files::FileOutputContext {
                            principal: ctx.principal.cloned(),
                            server: ctx.server.to_owned(),
                            tool: ctx.tool.to_owned(),
                            invocation_id: ctx.invocation_id.to_string(),
                        },
                        output,
                    )
                    .await
                {
                    Ok(prepared) => {
                        prepared_batch = prepared
                            .batch_id
                            .map(|batch_id| (batch_id, prepared.file_count));
                        Ok(prepared.result)
                    }
                    Err(error) => Err(InvocationError::Upstream(error)),
                },
                Err(error) => Err(error),
            };
        }

        if retained && ctx.facts().side_effects {
            if let Err(error) = result {
                ctx.pending_redactions.clear();
                result = Ok(super::retained_response::delivery_failure(
                    CallToolResult::success(Vec::new()),
                    error.kind(),
                ));
            }
        }
        self.enter_stage(InvocationStage::ValidateOutput);
        if let Err(error) = self.validate_output(ctx, &result).await {
            if let (Some(processor), Some((batch_id, _))) =
                (self.file_output_processor.as_ref(), prepared_batch.as_ref())
            {
                processor.discard(batch_id).await;
            }
            if retained && ctx.facts().side_effects {
                ctx.pending_redactions.clear();
                return Ok(Ok(super::retained_response::delivery_failure(
                    CallToolResult::success(Vec::new()),
                    error.kind(),
                )));
            }
            return Err(error);
        }
        if let (Some(processor), Some((batch_id, file_count))) =
            (self.file_output_processor.as_ref(), prepared_batch.as_ref())
        {
            if let Err(error) = processor.publish(batch_id, *file_count).await {
                processor.discard(batch_id).await;
                if retained && ctx.facts().side_effects {
                    ctx.pending_redactions.clear();
                    return Ok(Ok(super::retained_response::delivery_failure(
                        CallToolResult::success(Vec::new()),
                        "retained_response_publication_failed",
                    )));
                }
                return Ok(Err(InvocationError::Upstream(error)));
            }
        }
        // Existing retained responses and imported-file batches have their own
        // delivery contract. Compact only ordinary successful structured output
        // after its original schema and inspection controls have succeeded.
        if !retained && prepared_batch.is_none() {
            result = match result {
                Ok(output) => self.retain_large_inline_result(ctx, output).await,
                Err(error) => Err(error),
            };
        }
        Ok(result)
    }

    async fn retain_large_inline_result(
        &self,
        ctx: &mut InvocationContext<'_>,
        output: CallToolResult,
    ) -> Result<CallToolResult, InvocationError> {
        let Some(processor) = self.file_output_processor.as_ref() else {
            return Ok(output);
        };
        let Some(threshold) = processor.inline_response_threshold_bytes() else {
            return Ok(output);
        };
        if ctx.response_delivery != waygate_invocation::ResponseDelivery::File
            || ctx.principal.is_none()
            || output.is_error == Some(true)
            || output.structured_content.is_none()
        {
            return Ok(output);
        }
        let bytes = match serde_json::to_vec(&output) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Self::inline_delivery_failure(
                    ctx,
                    CallToolResult::success(Vec::new()),
                    rmcp::ErrorData::internal_error("tool response could not be encoded", None),
                )
            }
        };
        if bytes.len() <= threshold {
            return Ok(output);
        }
        let trust = super::result_trust::parse(&output).ok();
        let sensitive = trust.map_or(ctx.facts().pii, |trust| trust.sensitive);
        let mut compact = CallToolResult::success(Vec::new());
        // Carry only bounded trust labels into the compact envelope. All
        // original metadata, text and structured data remain in the saved file.
        compact.meta.get_or_insert_with(Default::default).insert(
            "io.modelcontextprotocol/trust-annotations".to_owned(),
            serde_json::json!({"sensitive": sensitive, "untrusted": trust.is_none_or(|trust| trust.untrusted)}),
        );
        let prepared = processor
            .prepare_retained(
                crate::files::FileOutputContext {
                    principal: ctx.principal.cloned(),
                    server: ctx.server.to_owned(),
                    tool: ctx.tool.to_owned(),
                    invocation_id: ctx.invocation_id.to_string(),
                },
                crate::files::RetainedFileBody {
                    upstream_uri: format!("gateway-response:{}", ctx.invocation_id),
                    media_type: "application/json".to_owned(),
                    bytes,
                    sensitive: sensitive || ctx.facts().pii,
                },
            )
            .await;
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(error) => return Self::inline_delivery_failure(ctx, compact, error),
        };
        crate::retained_delivery::attach(
            &mut compact,
            crate::retained_delivery::Delivery::File {
                operation_status: crate::retained_delivery::OperationStatus::Succeeded,
                file: prepared.file.clone(),
            },
        );
        compact
            .content
            .push(rmcp::model::ContentBlock::resource_link(
                rmcp::model::Resource::new(prepared.file.uri, "Complete tool result")
                    .with_mime_type("application/json"),
            ));
        let valid = compact
            .structured_content
            .as_ref()
            .is_some_and(|value| crate::retained_delivery::validator().is_valid(value));
        if !valid {
            processor.discard(&prepared.batch_id).await;
            return Self::inline_delivery_failure(
                ctx,
                CallToolResult::success(Vec::new()),
                rmcp::ErrorData::internal_error("retained delivery descriptor is invalid", None),
            );
        }
        if let Err(error) = processor.publish(&prepared.batch_id, 1).await {
            processor.discard(&prepared.batch_id).await;
            return Self::inline_delivery_failure(ctx, CallToolResult::success(Vec::new()), error);
        }
        Ok(compact)
    }

    fn inline_delivery_failure(
        ctx: &mut InvocationContext<'_>,
        compact: CallToolResult,
        error: rmcp::ErrorData,
    ) -> Result<CallToolResult, InvocationError> {
        if ctx.facts().side_effects {
            ctx.pending_redactions.clear();
            Ok(super::retained_response::delivery_failure(
                compact,
                "inline_response_delivery_failed",
            ))
        } else {
            Err(InvocationError::Upstream(error))
        }
    }
}
