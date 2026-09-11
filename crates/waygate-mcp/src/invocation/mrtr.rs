//! MRTR (SEP-2322) answerability and content inspection for the invocation
//! pipeline: whether an upstream `input_required` pause can round-trip with
//! the downstream caller that started the call, and whether the configured
//! response-security controls admit its upstream-authored content.

use waygate_invocation::InvocationError;

use super::{result_trust, DefaultInvocationService, InvocationContext};

impl DefaultInvocationService {
    /// Admit or refuse an upstream MRTR pause, in order:
    ///
    /// 1. any pause on an approval-gated call is refused — the call is
    ///    single-round and its retry could never re-authorize, so the
    ///    refusal names the consumed grant;
    /// 2. a pause with neither input requests nor request state is refused
    ///    as malformed — no retry could make progress;
    /// 3. a pause claiming the gateway's reserved approval key cannot
    ///    round-trip (the retry strip would consume the caller's answer as
    ///    the gateway's own ask) — refused loud;
    /// 4. a pause the caller cannot receive or answer fails closed with the
    ///    spec's `MISSING_REQUIRED_CLIENT_CAPABILITY` rather than stranding
    ///    the call;
    /// 5. the mandatory result-release controls scan the pause
    ///    ([`Self::inspect_pause`]: the annotation-native trust gate, then
    ///    the configured response inspectors); any finding refuses the
    ///    relay.
    ///
    /// An admitted pause is returned unchanged for verbatim relay —
    /// requests, opaque `requestState`, everything (the plan's locked
    /// decision; the gateway mints no request state). The orchestrator
    /// skips the schema-validation stage for it deliberately (a pause has
    /// no tool result to validate) and records the leg's own outcome row
    /// via [`Self::record_pause_relay`] — an upstream RPC occurred, and an
    /// abandoned round trip must still leave evidence. The retry that
    /// completes the call re-enters the pipeline as an ordinary call whose
    /// final result gets the full inspection/validation/outcome treatment.
    pub(super) async fn admit_pause(
        &self,
        ctx: &mut InvocationContext<'_>,
        mut pause: rmcp::model::InputRequiredResult,
    ) -> Result<rmcp::model::InputRequiredResult, InvocationError> {
        // An approval-gated call is single-round: its retry could never
        // re-authorize (the one-time grant is already consumed, and the
        // retry's continuation inputs would be refused pre-claim), so ANY
        // pause — including a capability-free state-only one, which no
        // capability clearing can prevent an upstream from returning — is
        // refused with a teach-through that names what actually happened.
        // The consumed grant is the same cost as any post-claim dispatch
        // failure (a grant covers one dispatch attempt, not one success);
        // naming it here keeps the caller from retrying into further burns.
        let approval_gated = ctx.facts().requires_approval || ctx.cedar_approval_policies.is_some();
        if approval_gated {
            return Err(InvocationError::Upstream(rmcp::ErrorData::internal_error(
                format!(
                    "`{}.{}` requires human approval and is single-round, but the upstream \
                     paused mid-call; the claimed grant was consumed by this attempt — obtain \
                     a new grant before retrying",
                    ctx.server, ctx.tool
                ),
                None,
            )));
        }
        // A pause carrying neither an input request nor request state gives
        // the caller nothing to answer and nothing to echo — no retry can
        // make progress, so relaying it would strand the call. Refuse it as
        // the malformed upstream response it is.
        let no_requests = pause
            .input_requests
            .as_ref()
            .is_none_or(|requests| requests.is_empty());
        if no_requests && pause.request_state.is_none() {
            return Err(InvocationError::Upstream(rmcp::ErrorData::internal_error(
                format!(
                    "upstream `{}` paused with neither input requests nor request state; \
                     the pause cannot make progress and was not relayed",
                    ctx.server
                ),
                None,
            )));
        }
        if pause_collides_with_reserved_key(&pause) {
            return Err(reserved_key_collision_error(ctx.server));
        }
        if let Some((capability, detail)) =
            unanswerable_input_request(&pause, ctx.mrtr.caller_capabilities.as_ref())
        {
            return Err(InvocationError::Upstream(rmcp::ErrorData::new(
                rmcp::model::ErrorCode::MISSING_REQUIRED_CLIENT_CAPABILITY,
                format!(
                    "`{}.{}` paused for client-side input that cannot round-trip: {detail}",
                    ctx.server, ctx.tool
                ),
                Some(serde_json::json!({
                    "error": "missing_required_client_capability",
                    "capability": capability,
                })),
            )));
        }
        self.inspect_pause(ctx, &pause).await?;
        self.seal_pause_state(ctx, &mut pause)?;
        Ok(pause)
    }

    /// Replace the relayed pause's state with the gateway's sealed envelope
    /// around it.
    ///
    /// The gateway is a server at its own hop, and its own continuation
    /// state does influence authorization — it is what tells a later retry
    /// apart from a caller-assembled one — so the protocol requires it to be
    /// integrity-protected and bound to the principal and originating
    /// request. The upstream's own opaque blob rides inside untouched and is
    /// restored before dispatch, so the upstream sees exactly what it minted
    /// (or nothing, when it minted nothing). Conformant clients echo the
    /// value without inspecting it, so this is transparent to them.
    ///
    /// Without a configured seal key the pause relays exactly as before;
    /// only the elicited-file path, which needs the provenance, is refused.
    fn seal_pause_state(
        &self,
        ctx: &InvocationContext<'_>,
        pause: &mut rmcp::model::InputRequiredResult,
    ) -> Result<(), InvocationError> {
        let (Some(sealer), Some(principal)) = (self.continuation_sealer.as_ref(), ctx.principal)
        else {
            return Ok(());
        };
        let contract = contract_text(ctx);
        let sealed = sealer
            .seal(
                principal,
                &call_identity(ctx, &contract),
                pause.input_requests.as_ref(),
                pause.request_state.take(),
            )
            .map_err(|error| {
                tracing::warn!(server = %ctx.server, tool = %ctx.tool, %error, "continuation state could not be sealed");
                InvocationError::Upstream(rmcp::ErrorData::internal_error(
                    "continuation state could not be sealed",
                    None,
                ))
            })?;
        pause.request_state = Some(sealed);
        Ok(())
    }

    /// Verify a caller-presented continuation and restore the upstream's own
    /// state before dispatch.
    ///
    /// Runs before quota and the approval claim, so a forged, transplanted,
    /// or expired envelope costs the caller nothing and takes no authority.
    /// Success records on the call that this retry provably answers a pause
    /// this gateway relayed to this principal for this tool — the fact
    /// elicited-file delivery depends on.
    pub(super) fn verify_continuation(
        &self,
        ctx: &mut InvocationContext<'_>,
    ) -> Result<(), InvocationError> {
        // Taken here, ahead of file-input rewriting, so the digest names the
        // call the caller authored rather than the arguments this leg
        // happens to dispatch — the pausing leg's file arguments are
        // rewritten to freshly authorized upstream URIs and would never
        // match a retry's.
        ctx.continuation.digest = waygate_catalog::argument_hash(ctx.arguments.as_ref());
        let Some(sealer) = self.continuation_sealer.as_ref() else {
            return Ok(());
        };
        let Some(sealed) = ctx.mrtr.request_state.clone() else {
            return Ok(());
        };
        // With no authenticated caller there was no principal to seal against
        // on the pausing leg either, so this state is the upstream's own and
        // is forwarded as it always was. Delivery stays unauthorized, which
        // is what withholds elicited files from an unauthenticated caller.
        let Some(principal) = ctx.principal else {
            return Ok(());
        };
        let answered = ctx
            .mrtr
            .input_responses
            .iter()
            .flat_map(|responses| responses.keys().cloned());
        let contract = contract_text(ctx);
        let opened = sealer.open(principal, &call_identity(ctx, &contract), &sealed, answered);
        match opened {
            Ok(verified) => {
                ctx.mrtr.request_state = verified.upstream_state;
                ctx.continuation.deliverable_keys = Some(verified.deliverable_keys);
                Ok(())
            }
            Err(error) => {
                tracing::warn!(
                    server = %ctx.server,
                    tool = %ctx.tool,
                    ?error,
                    "continuation state failed verification"
                );
                Err(InvocationError::InvalidArguments(format!(
                    "`{}.{}` received continuation state this gateway did not issue for this \
                     caller and tool; retry the original request",
                    ctx.server, ctx.tool
                )))
            }
        }
    }

    /// Record the outcome row for a relayed pause.
    ///
    /// The pausing leg performed a real upstream RPC, and the default
    /// best-effort evidence posture writes no pre-call row — so without
    /// this row an abandoned round trip would leave no audit trace at all.
    /// The row is a `Success` (the leg completed exactly as the protocol
    /// allows) whose reason names the pause, mirroring how a policy-gated
    /// success row carries its marker; the completing retry writes its own
    /// ordinary outcome row.
    pub(super) async fn record_pause_relay(&self, ctx: &mut InvocationContext<'_>) {
        let facts = ctx.facts();
        let (scopes, auth_method, roles, side_effects) =
            super::decision_inputs(ctx.principal, facts);
        let latency_ms = ctx.latency_ms.unwrap_or(0);
        let event = ctx
            .audit_event("CallTool", crate::audit::AuditOutcome::Success)
            .with_category(ctx.audit_category)
            .with_principal(ctx.principal)
            .with_tool(ctx.server, ctx.tool)
            .with_risk(facts.risk)
            .with_pii(facts.pii)
            .with_policies(ctx.authz_policy_ids.clone())
            .with_decision_inputs(scopes, auth_method, roles, side_effects)
            .with_latency_ms(latency_ms)
            .with_reason("upstream paused for client input (input_required); awaiting retry");
        self.audit.record_chained_best_effort(event).await;
    }

    /// Run the mandatory result-release controls over an MRTR pause before
    /// it is relayed.
    ///
    /// A pause is caller-visible upstream content — elicitation messages,
    /// sampling prompts, the opaque `requestState` — so every control that
    /// governs a returned `CallToolResult` must see it, in the same order
    /// the response stage applies them:
    ///
    /// 1. the annotation-native result-trust gate, when the admitted
    ///    contract enforces trust claims. The pause's own `_meta` carries
    ///    (or fails to carry) the labels — an annotation-native upstream
    ///    that wants MRTR must label its pauses exactly as it labels
    ///    results, and an unlabeled or over-sensitive pause is withheld
    ///    with the gate's ordinary audit trail;
    /// 2. the configured response-inspector chain, over a serialized view
    ///    of the whole pause. Any finding refuses the relay: a `Block` for
    ///    the usual reason, and a `Redact` too, because a pause is an
    ///    interactive prompt the caller is about to answer — forwarding a
    ///    silently rewritten prompt could change what the human consents
    ///    to, and the retry round trip needs the upstream's requests
    ///    byte-faithful.
    ///
    /// Refusal is the fail-closed direction and reuses the ordinary
    /// blocked-response audit path.
    pub(super) async fn inspect_pause(
        &self,
        ctx: &mut InvocationContext<'_>,
        pause: &rmcp::model::InputRequiredResult,
    ) -> Result<(), InvocationError> {
        let annotation_enforced = ctx.tool_snapshot().annotation_claims_enforced();
        if !annotation_enforced && self.inspectors.is_empty() {
            return Ok(());
        }
        let serialized = serde_json::to_value(pause).map_err(|_| {
            InvocationError::Upstream(rmcp::ErrorData::internal_error(
                "upstream input_required pause could not be serialized for inspection",
                None,
            ))
        })?;
        let mut view = rmcp::model::CallToolResult::structured(serialized);
        // The trust labels ride the pause's own `_meta`, exactly where a
        // completed result carries them.
        view.meta = pause.meta.clone();
        if annotation_enforced {
            let anticipated = ctx.tool_snapshot().anticipated_sensitive_output();
            result_trust::enforce(&self.audit, ctx, &view, anticipated).await?;
        }
        let (risk, pii) = {
            let facts = ctx.facts();
            (facts.risk, facts.pii)
        };
        let inspector_ctx = crate::inspection::InspectionContext {
            tenant: ctx
                .principal
                .map(|p| p.tenant.as_str())
                .unwrap_or(waygate_core::TenantId::DEFAULT),
            principal_sub: ctx.principal.map(|p| p.sub.as_str()),
            server: ctx.server,
            tool: ctx.tool,
            risk,
            pii_classified: pii,
        };
        for inspector in &self.inspectors {
            let reason = match inspector.inspect(&inspector_ctx, &view).await {
                crate::inspection::Decision::Pass => continue,
                crate::inspection::Decision::Block { reason } => reason,
                crate::inspection::Decision::Redact { findings_count, .. } => format!(
                    "{findings_count} finding(s) in an input_required pause, which cannot be \
                     redacted and forwarded"
                ),
            };
            return Err(
                result_trust::block_response(&self.audit, ctx, inspector.name(), reason).await,
            );
        }
        Ok(())
    }
}

/// Refuse MRTR continuation inputs on an approval-gated call.
///
/// The operator's grant is bound to exactly the reviewed tool + argument
/// hash; `inputResponses` and `requestState` are caller-controlled inputs
/// OUTSIDE that hash, so forwarding them would let unreviewed input alter
/// an approval-gated effect while still matching the grant. An
/// approval-gated call is single-round (the dispatch also advertises no
/// input capabilities, so a conforming upstream never solicits these
/// fields), which makes any continuation input on such a call a contract
/// violation to refuse loud — not silently drop, which would let the
/// caller believe its answers were delivered.
///
/// Must run BEFORE `check_quota` and BEFORE `check_approval`: the grant
/// claim is atomic and one-time, so a refusal after it would burn the
/// operator's approval on a call that never dispatched.
/// The admitted contract, serialized for comparison as text.
///
/// A pause and its retry are separate calls, and a catalog or manifest
/// reload between them can put a different contract behind the same server
/// and tool. Sealing this makes that swap invalidate the pause.
fn contract_text(ctx: &InvocationContext<'_>) -> String {
    serde_json::to_string(&ctx.tool_snapshot().contract_identity()).unwrap_or_default()
}

/// What a pause and its retry must agree on to be the same call.
fn call_identity<'a>(
    ctx: &'a InvocationContext<'_>,
    contract: &'a str,
) -> super::continuation::CallIdentity<'a> {
    super::continuation::CallIdentity {
        server: ctx.server,
        tool: ctx.tool,
        digest: &ctx.continuation.digest,
        contract,
    }
}

pub(super) fn refuse_continuation_inputs_when_approval_gated(
    ctx: &InvocationContext<'_>,
) -> Result<(), InvocationError> {
    let approval_gated = ctx.facts().requires_approval || ctx.cedar_approval_policies.is_some();
    if !approval_gated {
        return Ok(());
    }
    if ctx.mrtr.input_responses.is_some() || ctx.mrtr.request_state.is_some() {
        return Err(InvocationError::InvalidArguments(format!(
            "`{}.{}` requires human approval and is single-round: the approved call carries \
             no `inputResponses` or `requestState`; retry with exactly the approved arguments",
            ctx.server, ctx.tool
        )));
    }
    Ok(())
}

/// Reserved key for the gateway's own approval ask inside an MRTR
/// `input_required` pause.
///
/// The reservation is enforced in both directions so the key is
/// unambiguous end to end: the adapter strips this key's answer from a
/// retry (it is addressed to the gateway — the operator's grant claim
/// authorizes, not the elicitation answer), and the pipeline refuses to
/// relay an *upstream* pause that uses the key
/// ([`pause_collides_with_reserved_key`]). Without the relay-side refusal
/// the retry-side strip would silently delete a legitimate upstream
/// continuation that happened to pick the same opaque key.
pub(crate) const APPROVAL_INPUT_REQUEST_KEY: &str = "gateway:approval";

/// Whether an upstream pause claims the gateway's reserved input-request
/// key. Such a pause cannot round-trip: the caller's answer under that key
/// would be consumed by the gateway's approval strip, so the collision is
/// refused loud at relay time instead of losing the answer silently later.
pub(super) fn pause_collides_with_reserved_key(pause: &rmcp::model::InputRequiredResult) -> bool {
    pause
        .input_requests
        .as_ref()
        .is_some_and(|requests| requests.contains_key(APPROVAL_INPUT_REQUEST_KEY))
}

/// The teach-through refusal for a reserved-key collision
/// ([`pause_collides_with_reserved_key`]), naming the key and why the
/// pause cannot be relayed.
pub(super) fn reserved_key_collision_error(server: &str) -> waygate_invocation::InvocationError {
    waygate_invocation::InvocationError::Upstream(rmcp::ErrorData::internal_error(
        format!(
            "upstream `{server}` paused with the reserved `{APPROVAL_INPUT_REQUEST_KEY}` \
             input-request key, which the gateway uses for its own approval ask; the pause \
             cannot be relayed"
        ),
        None,
    ))
}

/// Why an MRTR pause cannot round-trip with this caller — as a
/// `(capability label, refusal detail)` pair for the first blocked input
/// request — or `None` when the pause is deliverable and every request in
/// it is one the gateway relays and the caller declared it can answer.
///
/// The gateway relays exactly one input-request kind: elicitation.
/// Sampling and roots are deprecated in MCP 2026-07-28 and the repo's
/// deprecation posture builds no passthrough for them, so those requests
/// refuse regardless of what the caller declared.
///
/// `caller` is `None` for a caller whose transport cannot receive an
/// `input_required` result at all (legacy session, Code Mode, LLM surface):
/// every pause is then undeliverable, including a request-less pure
/// `requestState` round trip. `Some(empty)` is a 2026 caller that declared
/// nothing — it can receive and echo a state-only pause, but answers no
/// input request.
pub(super) fn unanswerable_input_request(
    pause: &rmcp::model::InputRequiredResult,
    caller: Option<&rmcp::model::ClientCapabilities>,
) -> Option<(&'static str, &'static str)> {
    let Some(caller) = caller else {
        return Some((
            "input_required",
            "this caller cannot receive an input_required result (it requires the \
             2026-07-28 multi-round-trip flow)",
        ));
    };
    let requests = pause.input_requests.as_ref()?;
    for request in requests.values() {
        // Elicitation is the only input-request kind the gateway relays.
        // Sampling and roots are deprecated in MCP 2026-07-28 and this
        // gateway's deprecation posture builds no passthrough for them —
        // declaring the capability would not help, and the refusal says so
        // instead of inviting a doomed re-declare-and-retry.
        let refusal = match request {
            rmcp::model::InputRequest::Elicitation(_) if caller.elicitation.is_some() => continue,
            rmcp::model::InputRequest::Elicitation(_) => (
                "elicitation",
                "the caller did not declare the elicitation capability; retry from a client \
                 that declares it",
            ),
            rmcp::model::InputRequest::CreateMessage(_) => (
                "sampling",
                "this gateway does not relay sampling input requests (deprecated in MCP \
                 2026-07-28)",
            ),
            rmcp::model::InputRequest::ListRoots(_) => (
                "roots",
                "this gateway does not relay roots input requests (deprecated in MCP \
                 2026-07-28)",
            ),
            // `InputRequest` is non-exhaustive: a request kind this build
            // does not know cannot be answered.
            _ => ("unknown", "the input request kind is not recognized"),
        };
        return Some(refusal);
    }
    None
}
