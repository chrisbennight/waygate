//! Pre-parse authorization and metering on the SEP-2243 routing headers.
//!
//! MCP 2026-07-28 requires `Mcp-Method` / `Mcp-Name` on Streamable-HTTP
//! POSTs precisely so intermediaries can route and meter without parsing
//! JSON bodies. This middleware uses them to refuse obviously-denied
//! `tools/call` requests before the body is ever read: the Cedar decision
//! and a *non-consuming* quota probe run against facts derived from the
//! headers alone, and a denial is answered at the HTTP layer with the
//! same structured JSON-RPC `data` envelope, audit row, and authz metrics
//! the invocation pipeline's own deny paths produce.
//!
//! ## The invariant that defines this module
//!
//! **The gate may only deny — never allow, and never debit.** A pass
//! through this gate grants nothing: the full pipeline still runs every
//! stage, re-authorizes, and is the only place quota tokens are consumed.
//! And the gate never refuses a request the pipeline would have allowed:
//!
//! - It only evaluates tools whose facts are argument-independent
//!   (`InvocationToolSnapshot::facts_vary_by_arguments() == false`), so
//!   the facts it authorizes are byte-identical to the facts the
//!   pipeline's PIP would assemble for the same call — same
//!   `build_call_facts`, same `Direct` channel, same absent operation.
//!   Tools with per-operation classifications are never gated: their
//!   facts depend on arguments the gate refuses to parse.
//! - `AuthzVerdict::StepUpRequired` passes through: the gate refuses
//!   only outright denials; the pipeline owns the step-up shape.
//! - Authorization runs through `AuthzGate::probe_tool_call` — the
//!   side-effect-free twin of `authorize_tool_call` — never the
//!   consuming path: the production handle is the break-glass decorator,
//!   whose authorize path claims a single-use override token on a Deny.
//!   The probe reports a Deny only when no live token could convert it,
//!   so a break-glass-authorized emergency call is neither refused early
//!   nor has its token burned by an advisory evaluation.
//! - The quota probe runs only after the authorization probe reports
//!   Allow — mirroring the pipeline, where check_quota runs only after
//!   authorize allows — and never consumes a token (see
//!   `QuotaService::check`); its denial is one `check_and_consume` would
//!   have issued at the same instant, and quota store errors pass
//!   through exactly as the pipeline treats them (best-effort allow).
//! - Early refusals record `mcp_server_operation_duration_seconds`
//!   (`tools/call`, error) exactly as the handler does for the
//!   pipeline's refusals, so denied traffic never vanishes from the
//!   server-operation series just because it was refused early.
//!
//! The gate acts only on requests that declare the served new protocol
//! generation (`MCP-Protocol-Version: 2026-07-28`) — exactly the
//! requests whose header/body consistency the SDK enforces with the
//! canonical `HeaderMismatch` (`-32020`, never minted here). Within that
//! set a header-based denial can never block a request that would have
//! succeeded: either the body matches (the pipeline denies the same
//! call) or it doesn't (the SDK refuses it). Legacy requests carry no
//! enforced headers and pass through untouched; a future version the
//! gateway doesn't serve gets the version refusal, not a policy verdict.
//!
//! The denial responses carry `id: null`: the gate exists to *not* read
//! the body, so the JSON-RPC request id is unknowable — per JSON-RPC 2.0
//! the id member is null when it cannot be determined. The HTTP status
//! (403 / 429 with `Retry-After`) carries the machine-readable signal,
//! mirroring what `mcp_http_promote` produces for the pipeline's own
//! rate-limit denials.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, HeaderValue, Request, Response, StatusCode};
use axum::middleware::Next;
use waygate_mcp::audit::{AuditEvent, AuditOutcome, EvidenceCategory};
use waygate_mcp::authz::AuthzVerdict;
use waygate_mcp::catalog::ResolvedInvocationTool;
use waygate_oidc::Principal;

/// The SEP-2243 routing headers (rmcp enforces their presence and
/// body-consistency later in the stack; the gate only reads them).
const HEADER_MCP_METHOD: &str = "Mcp-Method";
const HEADER_MCP_NAME: &str = "Mcp-Name";
const HEADER_MCP_PROTOCOL_VERSION: &str = "MCP-Protocol-Version";

/// rmcp's marker for a base64-wrapped header value (a tool name that
/// wasn't header-safe). The gate passes such names through rather than
/// duplicating the SDK's decoding.
const BASE64_HEADER_MARKER: &str = "=?base64?";

/// Shared handles the gate evaluates with. All are the same instances the
/// invocation pipeline uses — same Cedar gate, same catalog resolution,
/// same quota service, same evidence recorder. Authz metric samples stay
/// one-per-request: the side-effect-free probe records nothing, and the
/// gate records the sample itself exactly when it terminates the request
/// (see `evaluate`).
pub struct GateState {
    pub catalog: waygate_mcp::SharedCatalog,
    pub authz: waygate_mcp::SharedAuthz,
    pub quota: Option<Arc<dyn waygate_quota::QuotaService>>,
    pub audit: waygate_mcp::SharedEvidence,
}

/// What the gate decided for one header-described call.
pub(crate) enum GateDecision {
    /// Not obviously denied (or not safely decidable pre-parse): hand the
    /// request to the full pipeline untouched.
    Pass,
    /// Cedar denied, and the denial holds for every possible body. Fields
    /// mirror the pipeline authorize stage's deny audit row.
    Forbidden {
        reason: String,
        policy_ids: Vec<String>,
        reasons: Vec<String>,
        risk: waygate_core::RiskTier,
        pii: bool,
        side_effects: bool,
    },
    /// The non-consuming quota probe found an exhausted bucket.
    RateLimited {
        policy_id: uuid::Uuid,
        policy_name: String,
        retry_after_seconds: u32,
        risk: waygate_core::RiskTier,
        pii: bool,
    },
}

/// Decide from `(principal, server, tool)` alone. Only ever returns a
/// non-`Pass` decision when that decision is argument-independent — see
/// the module docs for the exact conditions.
pub(crate) async fn evaluate(
    state: &GateState,
    principal: &Principal,
    server: &str,
    tool: &str,
) -> GateDecision {
    // The MCP handler routes several surfaces BEFORE the
    // `<server>.<tool>` upstream split: the built-in namespaces, the
    // per-server `searchTools` name, and the LLM plane's reserved namespace.
    // The `searchTools` name normally selects the compatibility adapter; on
    // MCP 2026 an actual upstream tool with that name takes precedence and
    // reaches the ordinary invocation pipeline. Pass either shape through
    // here: adapter calls have no catalog contract, while direct collisions
    // are fully re-authorized by the inner pipeline after route selection.
    // (`tools/call` names split at the FIRST dot, so a name ending in
    // `.searchTools` always leaves the suffix — bare or dotted — on the
    // tool side of the split.)
    if waygate_core::RESERVED_BUILTIN_NAMESPACES.contains(&server)
        || server == waygate_core::LLM_RESERVED_NAMESPACE
        || tool == "searchTools"
        || tool.ends_with(".searchTools")
    {
        return GateDecision::Pass;
    }
    let snapshot = match state
        .catalog
        .resolve_invocation_tool(principal.tenant.as_str(), server, tool)
        .await
    {
        ResolvedInvocationTool::Ready(snapshot) => snapshot,
        // The pipeline owns both the lifecycle refusal and the retryable
        // authoritative-catalog outage shape.
        ResolvedInvocationTool::Quarantined { .. } | ResolvedInvocationTool::Unavailable { .. } => {
            return GateDecision::Pass
        }
    };
    // Arguments can select a narrower per-operation classification; a
    // name-only decision is sound only when no argument can change the
    // facts.
    if snapshot.facts_vary_by_arguments() {
        return GateDecision::Pass;
    }
    let facts = snapshot.facts().clone();
    let call_facts = waygate_mcp::authz::build_call_facts(principal, &facts);
    // `build_call_facts` yields channel = Direct and operation = None —
    // exactly what the pipeline's extract_facts stamps for a direct call
    // to an argument-independent tool, so verdicts cannot diverge. The
    // PROBE, never `authorize_tool_call`: the production handle is the
    // break-glass decorator, whose authorize path claims a single-use
    // token on a Deny — an advisory evaluation must not consume the
    // authority the real dispatch needs.
    //
    // Authz DECISION sampling follows "whoever terminates the request
    // records its one sample": the probe itself records nothing, so
    // this gate records the decision exactly when it ends the request
    // here (the deny below, or the allow whose quota probe then
    // refuses), and every pass-through is sampled once by the
    // pipeline's own authorize_tool_call. The latency histogram is
    // different on purpose: it measures consuming-path evaluations
    // exclusively, so early-terminated requests contribute a decision
    // sample but no latency sample (the gate cannot observe the Cedar
    // evaluation's duration through the break-glass decorator).
    let probed = state.authz.probe_tool_call(&call_facts).await;
    match probed {
        waygate_mcp::authz::ProbeVerdict::Settled(AuthzVerdict::Deny {
            reason,
            policy_ids,
            reasons,
        }) => {
            // Decision counter only — never the latency histogram: the
            // gate cannot observe the Cedar evaluation's own duration
            // through the break-glass decorator (whose candidate lookup
            // is a DB round-trip), and a contaminated sample is worse
            // than an absent one. The latency histogram measures
            // consuming-path evaluations exclusively.
            waygate_telemetry::metrics::record_authz_decision("deny", facts.risk.as_str());
            return GateDecision::Forbidden {
                reason,
                policy_ids,
                reasons,
                risk: facts.risk,
                pii: facts.pii,
                side_effects: facts.side_effects,
            };
        }
        // Allow proceeds toward the quota probe — the pipeline reaches
        // check_quota only after authorize allows.
        waygate_mcp::authz::ProbeVerdict::Settled(AuthzVerdict::Allow { .. }) => {}
        // StepUpRequired and ApprovalRequired hand over IMMEDIATELY,
        // skipping the quota probe: the pipeline's authorize stage runs
        // before check_quota and owns those shapes, so probing quota
        // here could emit a 429 the pipeline would never produce for
        // this request (it would challenge for step-up first).
        waygate_mcp::authz::ProbeVerdict::Settled(
            AuthzVerdict::StepUpRequired { .. } | AuthzVerdict::ApprovalRequired { .. },
        ) => {
            return GateDecision::Pass;
        }
        // A consuming mechanism (a live break-glass token) could change
        // the settled verdict. Only the pipeline may perform that claim,
        // its BreakGlassUse evidence, and its metric samples — stand
        // fully aside, including from the quota probe.
        waygate_mcp::authz::ProbeVerdict::ConsumingOverridePossible => {
            return GateDecision::Pass;
        }
    }

    // API-key profile bounds run between authorize and check_quota in
    // the pipeline. A profile-restricted call must hand over: the
    // pipeline owns the profile refusal shape and audit row, and probing
    // quota here would leak quota policy metadata (ids, names) for a
    // tool the profile forbids this key from reaching at all.
    if let Some(restrictions) = principal.api_key_profile_restrictions.as_ref() {
        if waygate_mcp::invocation::evaluate_profile_restrictions(restrictions, server, tool)
            .is_err()
        {
            return GateDecision::Pass;
        }
    }

    if let Some(quota) = state.quota.as_ref() {
        // Same action derivation as the pipeline's check_quota: every
        // call falls under `Call`; side-effecting tools additionally
        // fall under `HighRiskCall`. Argument-independent facts make
        // this derivation exact, not conservative.
        let mut actions = vec![waygate_quota::QuotaAction::Call];
        if facts.side_effects {
            actions.push(waygate_quota::QuotaAction::HighRiskCall);
        }
        let qctx = waygate_quota::QuotaContext {
            tenant_id: principal.tenant.as_str().to_owned(),
            principal_sub: Some(principal.sub.clone()),
            client_id: None,
            server: server.to_owned(),
            fq_tool: format!("{server}.{tool}"),
        };
        match quota.check(&qctx, &actions).await {
            Err(waygate_quota::QuotaError::RateLimited {
                policy_id,
                name,
                retry_after_seconds,
            }) => {
                // This early 429 ends the request after an authz allow
                // that would otherwise go unsampled (the pipeline never
                // runs) — record the decision, mirroring the pipeline's
                // sequence of an allow followed by a quota refusal.
                // (Decision counter only; see the deny arm.)
                waygate_telemetry::metrics::record_authz_decision("allow", facts.risk.as_str());
                return GateDecision::RateLimited {
                    policy_id,
                    policy_name: name,
                    retry_after_seconds,
                    risk: facts.risk,
                    pii: facts.pii,
                };
            }
            // Allowed — or a store error, which the pipeline also treats
            // as best-effort allow rather than locking every tenant out.
            Ok(()) | Err(waygate_quota::QuotaError::Sqlx(_)) => {}
        }
    }
    GateDecision::Pass
}

/// Request middleware: read the routing headers, evaluate, and either
/// refuse at the HTTP layer or hand the untouched request (body never
/// read) to the inner service.
pub async fn preparse_gate(
    state: Arc<GateState>,
    req: Request<Body>,
    next: Next,
) -> Response<Body> {
    // Only POSTed tool calls are gated; everything else — other methods,
    // absent headers (the SDK enforces them for 2026-07-28 peers; legacy
    // peers don't send them), unqualified names (built-in tools) — passes
    // through untouched.
    if req.method() != axum::http::Method::POST {
        return next.run(req).await;
    }
    // Extract everything as owned values in one scope so no borrow of the
    // request (whose Body is !Sync) is held across an await.
    let extracted = {
        let header_str = |name: &str| {
            req.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        // Only requests that declare the new protocol generation are
        // gated. The SDK enforces Mcp-Method/Mcp-Name ↔ body consistency
        // only when MCP-Protocol-Version is present and ≥ 2026-07-28 —
        // on a legacy session the headers are unvalidated decoration, so
        // a header naming a denied tool could sit on a body naming an
        // allowed one and an early refusal would be a false denial. And
        // a future version the gateway doesn't serve must get the
        // version refusal, not a policy verdict — so the match is exact
        // against the served new-generation version, not a range.
        let new_generation = header_str(HEADER_MCP_PROTOCOL_VERSION).as_deref()
            == Some(waygate_mcp::MCP_SPEC_VERSION);
        match (
            new_generation,
            header_str(HEADER_MCP_METHOD).as_deref(),
            header_str(HEADER_MCP_NAME),
            req.extensions().get::<Principal>().cloned(),
        ) {
            (true, Some("tools/call"), Some(name), Some(principal))
                // A base64-wrapped name means characters the gate has no
                // business re-decoding; the pipeline sees the decoded
                // body name either way.
                if !name.starts_with(BASE64_HEADER_MARKER) =>
            {
                name.split_once('.')
                    .map(|(s, t)| (s.to_owned(), t.to_owned(), principal))
            }
            _ => None,
        }
    };
    let Some((server, tool, principal)) = extracted else {
        return next.run(req).await;
    };

    let started = std::time::Instant::now();
    match evaluate(&state, &principal, &server, &tool).await {
        GateDecision::Pass => next.run(req).await,
        GateDecision::Forbidden {
            reason,
            policy_ids,
            reasons,
            risk,
            pii,
            side_effects,
        } => {
            tracing::info!(
                user = %principal.sub,
                server = %server,
                tool = %tool,
                reason = %reason,
                policies = ?policy_ids,
                "tool call denied pre-parse (routing headers)",
            );
            // Mirror the pipeline authorize stage's deny row: same
            // action, outcome, category, and decision inputs, so the
            // activity feed and any SIEM rule see one shape regardless
            // of where the denial happened.
            let event = AuditEvent::new("CallTool", AuditOutcome::Denied)
                .with_category(EvidenceCategory::Invocation)
                .with_principal(Some(&principal))
                .with_tool(&server, &tool)
                .with_risk(risk)
                .with_pii(pii)
                .with_policies(policy_ids.clone())
                .with_decision_inputs(
                    principal.scopes.clone(),
                    Some(principal.auth_method.as_str().to_owned()),
                    principal.roles.clone(),
                    Some(side_effects),
                )
                .with_reason(&reason);
            state.audit.record_chained_best_effort(event).await;
            // The handler records this histogram for every pipeline
            // refusal; an early denial must appear in the same series.
            waygate_telemetry::metrics::record_server_operation(
                "tools/call",
                false,
                started.elapsed().as_secs_f64(),
            );
            let data = serde_json::json!({
                "error": "forbidden",
                "reason": reason,
                "policy_ids": policy_ids,
                "reasons": reasons,
            });
            refusal_response(
                StatusCode::FORBIDDEN,
                None,
                &format!("forbidden: {server}.{tool} — {reason}"),
                data,
            )
        }
        GateDecision::RateLimited {
            policy_id,
            policy_name,
            retry_after_seconds,
            risk,
            pii,
        } => {
            // Mirror the pipeline check_quota deny row.
            let event = AuditEvent::new("CallTool", AuditOutcome::Denied)
                .with_category(EvidenceCategory::Invocation)
                .with_principal(Some(&principal))
                .with_tool(&server, &tool)
                .with_risk(risk)
                .with_pii(pii)
                .with_reason(format!(
                    "rate_limited by policy `{policy_name}` ({policy_id}); \
                     retry_after_seconds={retry_after_seconds}"
                ));
            state.audit.record_chained_best_effort(event).await;
            waygate_telemetry::metrics::record_server_operation(
                "tools/call",
                false,
                started.elapsed().as_secs_f64(),
            );
            let data = serde_json::json!({
                "error": "rate_limited",
                "policy_id": policy_id.to_string(),
                "policy_name": policy_name,
                "retry_after_seconds": retry_after_seconds,
            });
            let retry = HeaderValue::from_str(&retry_after_seconds.to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("1"));
            refusal_response(
                StatusCode::TOO_MANY_REQUESTS,
                Some((header::RETRY_AFTER, retry)),
                &format!(
                    "rate-limited by policy `{policy_name}`; retry after {retry_after_seconds}s"
                ),
                data,
            )
        }
    }
}

/// Synthesize the refusal: HTTP status + optional header + a JSON-RPC
/// error envelope whose `error.data` matches the pipeline's structured
/// shape byte-for-byte. `id` is null — the body was never read, so the
/// request id is unknowable (JSON-RPC 2.0's rule for that case).
fn refusal_response(
    status: StatusCode,
    extra_header: Option<(axum::http::HeaderName, HeaderValue)>,
    message: &str,
    data: serde_json::Value,
) -> Response<Body> {
    let envelope = serde_json::json!({
        "jsonrpc": "2.0",
        "id": null,
        "error": {
            // INVALID_REQUEST — the same code the rmcp adapter uses for
            // the pipeline's forbidden / rate_limited errors.
            "code": -32600,
            "message": message,
            "data": data,
        }
    });
    let mut resp = Response::new(Body::from(envelope.to_string()));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Some((name, value)) = extra_header {
        resp.headers_mut().insert(name, value);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use async_trait::async_trait;
    use axum::routing::post;
    use axum::Router;
    use rmcp::model::{CallToolResult, Tool};
    use rmcp::ErrorData as McpError;
    use serde_json::json;
    use tower::ServiceExt;
    use waygate_mcp::audit::InMemorySink;
    use waygate_mcp::authz::{AuthzGate, ToolFacts};
    use waygate_mcp::catalog::{InvocationToolSnapshot, OperationClassification, UpstreamCatalog};
    use waygate_mcp::protocol::RiskTier;
    use waygate_oidc::AuthMethod;

    fn principal() -> Principal {
        Principal {
            sub: "alice".into(),
            email: None,
            groups: vec![],
            issuer: "test".into(),
            scopes: vec!["mcp:invoke".into()],
            tenant: waygate_core::TenantId::default(),
            auth_method: AuthMethod::Oauth,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        }
    }

    fn base_facts(server: &str, tool: &str) -> ToolFacts {
        ToolFacts {
            server: server.into(),
            name: tool.into(),
            risk: RiskTier::Low,
            side_effects: true,
            pii: false,
            requires_approval: false,
            requires_approval_known: true,
        }
    }

    /// Catalog whose resolution is scripted per test; counts resolves so
    /// pre-split surfaces can assert they never reach it.
    struct ScriptedCatalog {
        resolution: Mutex<Option<ResolvedInvocationTool>>,
        resolves: AtomicUsize,
    }

    #[async_trait]
    impl UpstreamCatalog for ScriptedCatalog {
        async fn list_servers(&self) -> Vec<String> {
            vec![]
        }
        async fn list_tools(&self, _server: &str) -> Result<Vec<Tool>, McpError> {
            Ok(Vec::new())
        }
        async fn call_tool(
            &self,
            _server: &str,
            _tool: &str,
            _args: Option<rmcp::model::JsonObject>,
            _principal: Option<&Principal>,
            _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
        ) -> Result<CallToolResult, McpError> {
            Err(McpError::internal_error("not under test", None))
        }
        async fn resolve_invocation_tool(
            &self,
            _tenant: &str,
            _server: &str,
            _tool: &str,
        ) -> ResolvedInvocationTool {
            self.resolves.fetch_add(1, Ordering::SeqCst);
            self.resolution
                .lock()
                .unwrap()
                .clone()
                .expect("test scripted a resolution")
        }
    }

    /// Authz gate with a scripted probe outcome; counts calls so
    /// pass-through paths can assert the engine was never consulted.
    struct ScriptedAuthz {
        verdict: waygate_mcp::authz::ProbeVerdict,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl AuthzGate for ScriptedAuthz {
        async fn may_discover_server(&self, _p: &Principal, _s: &str) -> bool {
            true
        }
        async fn authorize_resource_read(
            &self,
            _p: &Principal,
            _s: &str,
            _u: &str,
            _risk: waygate_core::RiskTier,
        ) -> AuthzVerdict {
            AuthzVerdict::Allow {
                policy_ids: Vec::new(),
            }
        }
        async fn authorize_tool_call(&self, _facts: &waygate_core::Facts) -> AuthzVerdict {
            // The production handle's authorize path consumes per-call
            // authority (break-glass claims a single-use token). The gate
            // must only ever use the side-effect-free probe.
            panic!("the pre-parse gate must never call the consuming authorize path");
        }
        async fn probe_tool_call(
            &self,
            _facts: &waygate_core::Facts,
        ) -> waygate_mcp::authz::ProbeVerdict {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.verdict.clone()
        }
    }

    /// Quota whose consuming path panics: the gate must never debit.
    struct ProbeOnlyQuota {
        deny: bool,
    }

    #[async_trait]
    impl waygate_quota::QuotaService for ProbeOnlyQuota {
        async fn check_and_consume(
            &self,
            _ctx: &waygate_quota::QuotaContext,
            _actions: &[waygate_quota::QuotaAction],
        ) -> Result<(), waygate_quota::QuotaError> {
            panic!("the pre-parse gate must never consume quota tokens");
        }
        async fn check(
            &self,
            _ctx: &waygate_quota::QuotaContext,
            _actions: &[waygate_quota::QuotaAction],
        ) -> Result<(), waygate_quota::QuotaError> {
            if self.deny {
                Err(waygate_quota::QuotaError::RateLimited {
                    policy_id: uuid::Uuid::from_u128(7),
                    name: "broad".into(),
                    retry_after_seconds: 42,
                })
            } else {
                Ok(())
            }
        }
    }

    struct Harness {
        state: Arc<GateState>,
        authz: Arc<ScriptedAuthz>,
        catalog: Arc<ScriptedCatalog>,
        audit: Arc<InMemorySink>,
        inner_hits: Arc<AtomicUsize>,
    }

    fn harness(
        verdict: waygate_mcp::authz::ProbeVerdict,
        resolution: ResolvedInvocationTool,
        quota_denies: Option<bool>,
    ) -> Harness {
        let authz = Arc::new(ScriptedAuthz {
            verdict,
            calls: AtomicUsize::new(0),
        });
        let catalog = Arc::new(ScriptedCatalog {
            resolution: Mutex::new(Some(resolution)),
            resolves: AtomicUsize::new(0),
        });
        let audit = Arc::new(InMemorySink::default());
        let state = Arc::new(GateState {
            catalog: catalog.clone(),
            authz: authz.clone(),
            quota: quota_denies.map(|deny| {
                Arc::new(ProbeOnlyQuota { deny }) as Arc<dyn waygate_quota::QuotaService>
            }),
            audit: audit.clone(),
        });
        Harness {
            state,
            authz,
            catalog,
            audit,
            inner_hits: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn app(h: &Harness) -> Router {
        let hits = h.inner_hits.clone();
        let state = h.state.clone();
        Router::new()
            .route(
                "/mcp",
                post(move || {
                    let hits = hits.clone();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        "inner"
                    }
                }),
            )
            .layer(axum::middleware::from_fn(move |req, next| {
                let state = state.clone();
                async move { preparse_gate(state, req, next).await }
            }))
    }

    fn call_req(name: &str, with_principal: bool) -> Request<Body> {
        versioned_call_req(name, with_principal, Some(waygate_mcp::MCP_SPEC_VERSION))
    }

    fn versioned_call_req(
        name: &str,
        with_principal: bool,
        version: Option<&str>,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header(HEADER_MCP_METHOD, "tools/call")
            .header(HEADER_MCP_NAME, name);
        if let Some(version) = version {
            builder = builder.header(HEADER_MCP_PROTOCOL_VERSION, version);
        }
        if with_principal {
            builder = builder.extension(principal());
        }
        builder.body(Body::from("{}")).unwrap()
    }

    fn deny_verdict() -> waygate_mcp::authz::ProbeVerdict {
        waygate_mcp::authz::ProbeVerdict::Settled(AuthzVerdict::Deny {
            reason: "blocked by policy".into(),
            policy_ids: vec!["policy0".into()],
            reasons: vec!["blocked by policy".into()],
        })
    }

    fn settled(verdict: AuthzVerdict) -> waygate_mcp::authz::ProbeVerdict {
        waygate_mcp::authz::ProbeVerdict::Settled(verdict)
    }

    fn ready(facts: ToolFacts) -> ResolvedInvocationTool {
        ResolvedInvocationTool::Ready(InvocationToolSnapshot::catalog_with_security_metadata(
            facts,
            uuid::Uuid::from_u128(1),
            "behavior-v1".into(),
            Some(json!({"type": "object"})),
            None,
            None,
            None,
        ))
    }

    #[tokio::test]
    async fn cedar_deny_refuses_before_the_body_with_the_pipeline_shape() {
        let h = harness(deny_verdict(), ready(base_facts("sig", "send")), None);
        let resp = app(&h)
            .oneshot(call_req("sig.send", true))
            .await
            .expect("dispatch");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"]["data"]["error"], "forbidden");
        assert_eq!(v["error"]["data"]["policy_ids"][0], "policy0");
        assert!(v["id"].is_null(), "the body was never read; id is null");
        assert_eq!(h.inner_hits.load(Ordering::SeqCst), 0, "denied before rmcp");
        let events = h.audit.snapshot().await;
        assert_eq!(events.len(), 1, "one Denied audit row, pipeline-shaped");
        assert_eq!(events[0].action, "CallTool");
    }

    #[tokio::test]
    async fn quota_probe_denial_refuses_with_retry_after_and_never_debits() {
        let h = harness(
            settled(AuthzVerdict::Allow { policy_ids: vec![] }),
            ready(base_facts("sig", "send")),
            Some(true),
        );
        let resp = app(&h)
            .oneshot(call_req("sig.send", true))
            .await
            .expect("dispatch");
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers()
                .get(header::RETRY_AFTER)
                .unwrap()
                .to_str()
                .unwrap(),
            "42"
        );
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"]["data"]["error"], "rate_limited");
        assert_eq!(v["error"]["data"]["retry_after_seconds"], 42);
        assert_eq!(h.inner_hits.load(Ordering::SeqCst), 0);
        assert_eq!(h.audit.snapshot().await.len(), 1);
        // ProbeOnlyQuota panics on check_and_consume — reaching this
        // point at all proves nothing was debited.
    }

    #[tokio::test]
    async fn allow_step_up_and_approval_required_all_pass_through() {
        for (verdict, quota_denies) in [
            // Allow proceeds to the quota probe, which allows here.
            (settled(AuthzVerdict::Allow { policy_ids: vec![] }), false),
            // StepUpRequired / ApprovalRequired must hand over even with
            // an EXHAUSTED quota bucket: the pipeline's authorize stage
            // runs before check_quota and owns those shapes, so the gate
            // must not emit a 429 the pipeline would never produce.
            (
                settled(AuthzVerdict::StepUpRequired {
                    required_scope: "mcp:invoke:high".into(),
                    reason: "high risk".into(),
                    policy_ids: vec![],
                }),
                true,
            ),
            (
                settled(AuthzVerdict::ApprovalRequired {
                    reason: "needs a human".into(),
                    policy_ids: vec![],
                }),
                true,
            ),
            // A possible break-glass conversion stands the gate fully
            // aside — even with an exhausted quota bucket, because only
            // the pipeline may claim, audit, and meter that path.
            (
                waygate_mcp::authz::ProbeVerdict::ConsumingOverridePossible,
                true,
            ),
        ] {
            let h = harness(
                verdict,
                ready(base_facts("sig", "send")),
                Some(quota_denies),
            );
            let resp = app(&h)
                .oneshot(call_req("sig.send", true))
                .await
                .expect("dispatch");
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(
                h.inner_hits.load(Ordering::SeqCst),
                1,
                "the gate only denies — every non-deny verdict reaches the pipeline"
            );
            assert!(
                h.audit.snapshot().await.is_empty(),
                "no audit row on pass-through"
            );
        }
    }

    #[tokio::test]
    async fn argument_dependent_tools_are_never_gated() {
        let snapshot = InvocationToolSnapshot::catalog_with_security_metadata(
            base_facts("sig", "multi"),
            uuid::Uuid::from_u128(2),
            "behavior-v1".into(),
            Some(json!({"type": "object"})),
            None,
            None,
            None,
        )
        .with_operation_classifications(
            Some("mode".into()),
            vec![OperationClassification {
                value: "read".into(),
                risk: RiskTier::Low,
                side_effects: false,
                pii: false,
            }],
        );
        let h = harness(
            deny_verdict(),
            ResolvedInvocationTool::Ready(snapshot),
            None,
        );
        let resp = app(&h)
            .oneshot(call_req("sig.multi", true))
            .await
            .expect("dispatch");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(h.inner_hits.load(Ordering::SeqCst), 1);
        assert_eq!(
            h.authz.calls.load(Ordering::SeqCst),
            0,
            "facts vary with arguments the gate refuses to parse — never evaluated"
        );
    }

    #[tokio::test]
    async fn quarantined_tools_pass_through_for_the_pipeline_refusal_shape() {
        let h = harness(
            deny_verdict(),
            ResolvedInvocationTool::Quarantined {
                server: "sig".into(),
                tool: "send".into(),
            },
            None,
        );
        let resp = app(&h)
            .oneshot(call_req("sig.send", true))
            .await
            .expect("dispatch");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(h.inner_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn pre_split_surfaces_never_reach_the_catalog() {
        for name in [
            "gateway-admin.propose_change",
            "gateway-observe.query_audit",
            "gateway-control.reload_config",
            "codemode.execute",
            "llm.some-model",
            "sig.searchTools",
            "a.b.searchTools",
        ] {
            let h = harness(deny_verdict(), ready(base_facts("x", "y")), None);
            let resp = app(&h)
                .oneshot(call_req(name, true))
                .await
                .expect("dispatch");
            assert_eq!(resp.status(), StatusCode::OK, "{name} must pass through");
            assert_eq!(h.inner_hits.load(Ordering::SeqCst), 1, "{name}");
            assert_eq!(
                h.catalog.resolves.load(Ordering::SeqCst),
                0,
                "{name} is routed before the upstream split — the gate must not consult \
                 the catalog about it"
            );
        }
    }

    #[tokio::test]
    async fn non_gated_requests_pass_untouched() {
        // Missing headers, other methods, unqualified names, no principal:
        // all pass through with the body intact.
        let cases: Vec<Request<Body>> = vec![
            // No Mcp-Method header.
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .extension(principal())
                .body(Body::from("{}"))
                .unwrap(),
            // Non-tools/call method header.
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(HEADER_MCP_METHOD, "tools/list")
                .extension(principal())
                .body(Body::from("{}"))
                .unwrap(),
            // Unqualified name (no dot).
            call_req("ping", true),
            // No principal extension.
            call_req("sig.send", false),
        ];
        for req in cases {
            let h = harness(deny_verdict(), ready(base_facts("sig", "send")), None);
            let resp = app(&h).oneshot(req).await.expect("dispatch");
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(h.inner_hits.load(Ordering::SeqCst), 1);
            assert_eq!(h.authz.calls.load(Ordering::SeqCst), 0);
        }
    }

    /// The SDK validates header/body consistency only for requests that
    /// declare the new protocol generation; on anything else the headers
    /// are unvalidated decoration and a header-based denial could be a
    /// false one. Legacy, absent, and future version declarations all
    /// pass through untouched — a future version must get the version
    /// refusal, not a policy verdict.
    #[tokio::test]
    async fn only_new_generation_requests_are_gated() {
        for version in [None, Some("2025-11-25"), Some("2099-01-01")] {
            let h = harness(deny_verdict(), ready(base_facts("sig", "send")), None);
            let resp = app(&h)
                .oneshot(versioned_call_req("sig.send", true, version))
                .await
                .expect("dispatch");
            assert_eq!(resp.status(), StatusCode::OK, "{version:?}");
            assert_eq!(h.inner_hits.load(Ordering::SeqCst), 1, "{version:?}");
            assert_eq!(
                h.authz.calls.load(Ordering::SeqCst),
                0,
                "{version:?}: without SDK header enforcement the gate must not act"
            );
        }
    }

    /// A base64-wrapped tool name is the SDK's encoding for
    /// non-header-safe characters; the gate refuses to re-decode it.
    #[tokio::test]
    async fn base64_wrapped_names_pass_through() {
        let h = harness(deny_verdict(), ready(base_facts("sig", "send")), None);
        let resp = app(&h)
            .oneshot(call_req("=?base64?c2lnLnNlbmQ=?=", true))
            .await
            .expect("dispatch");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(h.inner_hits.load(Ordering::SeqCst), 1);
        assert_eq!(h.authz.calls.load(Ordering::SeqCst), 0);
    }

    /// Profile bounds sit between authorize and quota in the pipeline: a
    /// key confined away from the named server must hand over — the
    /// pipeline owns the profile refusal shape, and the quota probe must
    /// not leak quota policy metadata across the profile boundary.
    #[tokio::test]
    async fn profile_restricted_calls_skip_the_quota_probe_and_pass_through() {
        let mut restricted = principal();
        restricted.api_key_profile_restrictions = Some(waygate_oidc::ApiKeyProfileRestrictions {
            profile_id: "prof-1".into(),
            profile_name: "read_only".into(),
            allowed_servers: Some(vec!["other".into()]),
            allowed_tools: None,
        });
        let h = harness(
            settled(AuthzVerdict::Allow { policy_ids: vec![] }),
            ready(base_facts("sig", "send")),
            // The quota probe would deny — but it must never run for a
            // profile-restricted call.
            Some(true),
        );
        let req = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header(HEADER_MCP_METHOD, "tools/call")
            .header(HEADER_MCP_NAME, "sig.send")
            .header(HEADER_MCP_PROTOCOL_VERSION, waygate_mcp::MCP_SPEC_VERSION)
            .extension(restricted)
            .body(Body::from("{}"))
            .unwrap();
        let resp = app(&h).oneshot(req).await.expect("dispatch");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(h.inner_hits.load(Ordering::SeqCst), 1);
        assert!(h.audit.snapshot().await.is_empty());
    }
}
