//! The real implementations of the `waygate-agent`
//! trait seams, wiring the bounded loop ([`waygate_agent::run_agent`]) to the
//! gateway's governed invocation plane.
//!
//! Three seams from `waygate-agent` get production impls here:
//!
//! - [`OpenAiAgentModel`] ([`AgentModel`]) — renders the canonical transcript +
//!   tools as an OpenAI Chat request, dispatches it **unary** through the shared
//!   invocation pipeline AS the agent's effective principal (so the model call
//!   inherits the same Cedar authz / budget / audit as a `/v1` call), and folds
//!   the reply into a [`ModelTurn`].
//! - [`UpstreamAgentDispatch`] ([`AgentToolDispatch`]) — exposes the agent's
//!   allowlisted **upstream** tools (each with its `side_effects` fact), routed
//!   through the governed pipeline, AND the governed read built-ins
//!   (`gateway-observe.*`: audit / resource reads / policy simulation) via the
//!   injected [`SharedAssistReadTools`] seam, which applies the SAME Cedar
//!   forbid-overlay + namespace scope floor a direct MCP call gets. Only the
//!   read namespace is reachable — the mutating `gateway-admin.*` /
//!   `gateway-control.*` built-ins stay off the chat agent (mutations remain
//!   HITL / direct MCP). The allowlist is **hard-enforced here** (an empty
//!   allowlist ⇒ no tools; a call to a non-allowlisted tool is refused before
//!   dispatch) — never via the profile `Some([])` sentinel, which the pipeline
//!   reads as *unrestricted* (see [`narrow_restrictions`]).
//! - [`RejectingApproval`] ([`ApprovalGate`]) — declines every side-effecting
//!   call. It is the conservative default for any context that does not wire
//!   the in-chat rendezvous ([`crate::chat_approvals`]'s `ChatApprovalGate`),
//!   honoring "no side effects without confirmation".
//!
//! Plus [`effective_principal`], which clones the human session principal and
//! narrows its call-restrictions to the agent allowlist **without ever
//! broadening** the human's own restrictions.

use std::collections::HashSet;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::chat_approvals::SharedChatApprovals;

use waygate_agent::{
    AgentError, AgentModel, AgentTool, AgentToolCall, AgentToolDispatch, ApprovalDecision,
    ApprovalGate, ModelTurn, ToolOutcome,
};
use waygate_invocation::{
    InvocationContractIdentity, InvocationRequest, InvocationResponse, SharedInvocation,
};
use waygate_llm_translate::{
    openai_chat_to_canonical_response, CanonicalMessage, CanonicalResponse, CanonicalTool,
    ContentPart, OutputContentPart, OutputItem, Role,
};
use waygate_mcp::{SharedAssistReadTools, UpstreamCatalog};
use waygate_oidc::{ApiKeyProfileRestrictions, Principal};
use waygate_upstream::UpstreamPool;

/// The reserved invocation server namespace for LLM models — mirrors
/// `waygate_server::llm::LLM_SERVER` and `dashboard_chat::LLM_SERVER` (both
/// defined in crates this one can't import from). The dispatch path keys models
/// under `("llm", <alias>)`.
const LLM_SERVER: &str = "llm";

/// Max length of a model-facing tool name (OpenAI/Anthropic both cap function
/// names at 64 chars and require `^[A-Za-z0-9_-]+$`).
const MAX_TOOL_NAME_LEN: usize = 64;

// ---------------------------------------------------------------------------
// Model seam
// ---------------------------------------------------------------------------

/// [`AgentModel`] over the shared invocation pipeline. One `complete` call =
/// one governed, unary LLM turn.
pub struct OpenAiAgentModel {
    invocation: SharedInvocation,
    /// The agent's effective principal — the human, narrowed to the allowlist.
    principal: Principal,
    /// Model alias to dispatch under (`("llm", alias)`).
    model_alias: String,
    /// `agent:<name>` attribution label, stamped on every invocation so the
    /// audit log records the agent that acted on behalf of the human.
    acting_agent: String,
    /// Optional sampling temperature.
    temperature: Option<f64>,
}

impl OpenAiAgentModel {
    pub fn new(
        invocation: SharedInvocation,
        principal: Principal,
        model_alias: impl Into<String>,
        acting_agent: impl Into<String>,
        temperature: Option<f64>,
    ) -> Self {
        Self {
            invocation,
            principal,
            model_alias: model_alias.into(),
            acting_agent: acting_agent.into(),
            temperature,
        }
    }
}

#[async_trait]
impl AgentModel for OpenAiAgentModel {
    async fn complete(
        &self,
        messages: &[CanonicalMessage],
        tools: &[CanonicalTool],
    ) -> Result<ModelTurn, AgentError> {
        let mut args = Map::new();
        args.insert("model".to_owned(), json!(self.model_alias));
        args.insert(
            "messages".to_owned(),
            Value::Array(canonical_messages_to_openai(messages)),
        );
        if !tools.is_empty() {
            args.insert(
                "tools".to_owned(),
                Value::Array(canonical_tools_to_openai(tools)),
            );
        }
        // Unary: the agent needs the whole turn (text + tool_calls) at once.
        args.insert("stream".to_owned(), json!(false));
        if let Some(t) = self.temperature {
            args.insert("temperature".to_owned(), json!(t));
        }

        let req = InvocationRequest::new(LLM_SERVER, self.model_alias.clone())
            .with_arguments(Some(args))
            .with_acting_agent(self.acting_agent.clone());

        let body = match self.invocation.invoke(Some(&self.principal), req).await {
            Ok(InvocationResponse::UnaryValue(body)) => body,
            Ok(InvocationResponse::Unary(_)) => {
                return Err(AgentError::Model(
                    "inference returned an MCP tool result on the model path".to_owned(),
                ));
            }
            Ok(InvocationResponse::Stream(_)) => {
                return Err(AgentError::Model(
                    "inference returned a streaming response on a non-streaming model call"
                        .to_owned(),
                ));
            }
            // The runtime declares no input capabilities on its requests, so
            // the pipeline fails an MRTR pause closed before it can surface
            // here; reaching this arm is a wiring bug.
            Ok(InvocationResponse::InputRequired(_)) => {
                return Err(AgentError::Model(
                    "inference returned an input_required pause on the model path".to_owned(),
                ));
            }
            Err(e) => return Err(AgentError::Model(e.to_string())),
        };

        // A provider/pipeline error surfaced as a JSON body (rather than an
        // `Err`) must not be silently folded into an empty final answer.
        if let Some(err) = body.get("error") {
            let msg = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("inference returned an error body");
            return Err(AgentError::Model(msg.to_owned()));
        }

        Ok(reduce_to_turn(openai_chat_to_canonical_response(&body)))
    }
}

/// Reduce a folded canonical response to a [`ModelTurn`]: the assistant message
/// (text part first, then any tool-use parts), the tool calls to execute, and
/// the turn's token usage.
fn reduce_to_turn(resp: CanonicalResponse) -> ModelTurn {
    let mut text = String::new();
    let mut tool_use: Vec<ContentPart> = Vec::new();
    let mut tool_calls: Vec<AgentToolCall> = Vec::new();

    for item in &resp.output {
        match item {
            OutputItem::Message { content, .. } => {
                for part in content {
                    if let OutputContentPart::OutputText { text: t, .. } = part {
                        text.push_str(t);
                    }
                }
            }
            OutputItem::FunctionCall {
                call_id,
                name,
                arguments,
                ..
            } => {
                tool_calls.push(AgentToolCall {
                    id: call_id.clone(),
                    name: name.clone(),
                    arguments: arguments.clone(),
                });
                tool_use.push(ContentPart::ToolUse {
                    id: call_id.clone(),
                    name: name.clone(),
                    arguments: arguments.clone(),
                });
            }
            // Reasoning / unknown items carry no chat-visible content.
            _ => {}
        }
    }

    let mut content: Vec<ContentPart> = Vec::new();
    if !text.is_empty() {
        content.push(ContentPart::Text { text });
    }
    content.extend(tool_use);
    // An assistant message must have ≥1 part for a valid transcript; a model
    // that produced neither text nor tool calls gets an empty-text part so the
    // loop can still treat it as a (blank) final answer.
    if content.is_empty() {
        content.push(ContentPart::Text {
            text: String::new(),
        });
    }

    let usage_tokens = resp
        .usage
        .as_ref()
        .map(|u| {
            u.total
                .unwrap_or_else(|| u.input.unwrap_or(0) + u.output.unwrap_or(0))
        })
        .unwrap_or(0);

    ModelTurn {
        assistant: CanonicalMessage {
            role: Role::Assistant,
            content,
        },
        tool_calls,
        usage_tokens,
    }
}

/// Render canonical messages into OpenAI Chat `messages[]`. The shape round-trips
/// through the pipeline's `parse_chat_completions` inbound parser.
fn canonical_messages_to_openai(messages: &[CanonicalMessage]) -> Vec<Value> {
    let mut out = Vec::with_capacity(messages.len());
    for m in messages {
        // A `Tool` message becomes one OpenAI `{role:"tool", tool_call_id,
        // content}` per result part.
        if matches!(m.role, Role::Tool) {
            for part in &m.content {
                if let ContentPart::ToolResult {
                    tool_call_id,
                    content,
                } = part
                {
                    out.push(json!({
                        "role": "tool",
                        "tool_call_id": tool_call_id,
                        "content": content,
                    }));
                }
            }
            continue;
        }

        let role = match m.role {
            Role::System => "system",
            Role::User => "user",
            Role::Assistant => "assistant",
            Role::Tool => unreachable!("handled above"),
        };
        let mut text = String::new();
        let mut tool_calls: Vec<Value> = Vec::new();
        for part in &m.content {
            match part {
                ContentPart::Text { text: t } => text.push_str(t),
                ContentPart::ToolUse {
                    id,
                    name,
                    arguments,
                } => tool_calls.push(json!({
                    "id": id,
                    "type": "function",
                    "function": { "name": name, "arguments": arguments },
                })),
                // ImageUrl / Reasoning are not produced on the agent path.
                _ => {}
            }
        }

        let mut msg = Map::new();
        msg.insert("role".to_owned(), json!(role));
        if tool_calls.is_empty() {
            msg.insert("content".to_owned(), json!(text));
        } else {
            // An assistant tool-call turn carries optional text + the calls.
            msg.insert(
                "content".to_owned(),
                if text.is_empty() {
                    Value::Null
                } else {
                    json!(text)
                },
            );
            msg.insert("tool_calls".to_owned(), Value::Array(tool_calls));
        }
        out.push(Value::Object(msg));
    }
    out
}

/// Render canonical tools into OpenAI Chat `tools[]` (`{type:"function", …}`).
fn canonical_tools_to_openai(tools: &[CanonicalTool]) -> Vec<Value> {
    tools
        .iter()
        .map(|t| {
            let mut f = Map::new();
            f.insert("name".to_owned(), json!(t.name));
            if let Some(d) = &t.description {
                f.insert("description".to_owned(), json!(d));
            }
            f.insert("parameters".to_owned(), t.parameters.clone());
            if let Some(s) = t.strict {
                f.insert("strict".to_owned(), json!(s));
            }
            json!({ "type": "function", "function": Value::Object(f) })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tool-dispatch seam
// ---------------------------------------------------------------------------

/// One resolved allowlisted tool: its model-facing (sanitized) name, the
/// fully-qualified `(server, tool)` it dispatches to, its `side_effects` fact,
/// and the model-facing definition.
#[derive(Debug, Clone)]
struct ResolvedTool {
    sensitive_input: bool,
    /// Sanitized, model-facing function name (`^[A-Za-z0-9_-]{1,64}$`).
    model_name: String,
    server: String,
    tool: String,
    side_effects: bool,
    /// The contract identity resolved at listing time, whose `side_effects`
    /// drove this tool's operator-approval decision. Pinned into the invocation
    /// so the pipeline refuses if the contract drifts before execution. `None`
    /// for built-ins (they don't ride the upstream pipeline) and for tools that
    /// would not resolve (treated as side-effecting; invocation refuses them).
    expected_contract: Option<InvocationContractIdentity>,
    definition: CanonicalTool,
    /// `true` ⇒ a governed read built-in (`gateway-observe.*`) dispatched via the
    /// [`SharedAssistReadTools`] seam; `false` ⇒ an upstream tool via the
    /// invocation pipeline.
    builtin: bool,
}

/// [`AgentToolDispatch`] over the agent's allowlist: upstream MCP tools via the
/// invocation pipeline, plus the governed read built-ins
/// (`gateway-observe.*`) via the [`SharedAssistReadTools`] seam. Pre-bound to the
/// agent's effective principal + its resolved allowlist.
pub struct UpstreamAgentDispatch {
    invocation: SharedInvocation,
    assist_read: Option<SharedAssistReadTools>,
    principal: Principal,
    acting_agent: String,
    tools: Vec<ResolvedTool>,
}

impl UpstreamAgentDispatch {
    /// Resolve the agent's fully-qualified `allowed_tools` allowlist. Upstream
    /// `server.tool` entries are resolved against the live pool; read built-in
    /// entries (`gateway-observe.*`) against `assist_read`. A listed tool whose
    /// server is unknown/disconnected, whose name isn't published, or (built-in)
    /// the principal can't see / isn't read-only is **skipped** (not offered, and
    /// a call to it is refused) — an allowlist entry is a permission, not a
    /// guarantee the tool is reachable.
    pub async fn resolve(
        invocation: SharedInvocation,
        pool: &UpstreamPool,
        assist_read: Option<SharedAssistReadTools>,
        principal: Principal,
        acting_agent: impl Into<String>,
        allowed_tools: &[String],
    ) -> Self {
        let mut tools: Vec<ResolvedTool> = Vec::new();
        let mut taken: HashSet<String> = HashSet::new();

        // The governed read built-ins this principal may call, indexed by their
        // fully-qualified name. Empty when no `assist_read` seam is wired.
        let builtin_index: std::collections::HashMap<String, waygate_mcp::AssistReadTool> =
            match assist_read.as_ref() {
                Some(a) => a
                    .read_tools(Some(&principal))
                    .await
                    .into_iter()
                    .map(|t| (t.name.clone(), t))
                    .collect(),
                None => std::collections::HashMap::new(),
            };

        for fq in allowed_tools {
            let Some((server, tool)) = fq.split_once('.') else {
                tracing::warn!(entry = %fq, "agent allowlist: entry is not `server.tool`; skipping");
                continue;
            };
            // Built-in namespaces don't ride the upstream pipeline. The read
            // (`gateway-observe`) namespace is dispatchable via the governed
            // `assist_read` seam (Cedar overlay + scope floor); any other
            // built-in namespace (propose/control) stays off the chat agent.
            if server.starts_with("gateway-") {
                if let Some(rt) = builtin_index.get(fq) {
                    let model_name = sanitize_tool_name(fq, &mut taken);
                    let description = (!rt.description.is_empty()).then(|| rt.description.clone());
                    tools.push(ResolvedTool {
                        sensitive_input: false,
                        model_name: model_name.clone(),
                        server: server.to_owned(),
                        tool: tool.to_owned(),
                        side_effects: rt.side_effects,
                        definition: CanonicalTool {
                            name: model_name,
                            description,
                            parameters: Value::Object(rt.input_schema.clone()),
                            strict: None,
                        },
                        expected_contract: None,
                        builtin: true,
                    });
                } else {
                    tracing::warn!(
                        entry = %fq,
                        "agent allowlist: built-in not callable from chat (not a read tool, \
                         unavailable, or not permitted); skipping"
                    );
                }
                continue;
            }
            // Description, sensitivity, schemas and dispatch identity come from
            // one admitted snapshot, so a reload cannot mix review generations.
            let waygate_mcp::catalog::ResolvedInvocationTool::Ready(snapshot) = pool
                .resolve_invocation_tool(principal.tenant.as_str(), server, tool)
                .await
            else {
                continue;
            };
            let Some(rmcp_tool) = snapshot.published_definition() else {
                continue;
            };
            let sensitive_input = snapshot
                .tool_annotations()
                .zip(snapshot.action_metadata())
                .is_some_and(|(annotations, metadata)| {
                    waygate_upstream::security_metadata::behavior_claims(annotations, metadata)
                        .map_or(true, |claims| claims.input_sensitive)
                });
            let side_effects = snapshot.facts().side_effects;
            let expected_contract = Some(snapshot.contract_identity());
            let model_name = sanitize_tool_name(fq, &mut taken);
            let parameters = Value::Object((*rmcp_tool.input_schema).clone());
            let definition = CanonicalTool {
                name: model_name.clone(),
                description: rmcp_tool.description.as_deref().map(str::to_owned),
                parameters,
                strict: None,
            };
            tools.push(ResolvedTool {
                sensitive_input,
                model_name,
                server: server.to_owned(),
                tool: tool.to_owned(),
                side_effects,
                expected_contract,
                definition,
                builtin: false,
            });
        }

        Self {
            invocation,
            assist_read,
            principal,
            acting_agent: acting_agent.into(),
            tools,
        }
    }
}

#[async_trait]
impl AgentToolDispatch for UpstreamAgentDispatch {
    fn approval_preview(&self, name: &str, arguments: &str) -> String {
        let Some(tool) = self.tools.iter().find(|tool| tool.model_name == name) else {
            return "Tool is not available for dispatch.".to_owned();
        };
        if !tool.sensitive_input {
            return arguments.to_owned();
        }
        let parsed = serde_json::from_str::<Value>(arguments).ok();
        let fields: Vec<_> = tool
            .definition
            .parameters
            .get("properties")
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(|fields| fields.keys())
            .filter(|name| {
                parsed
                    .as_ref()
                    .is_some_and(|value| value.get(name.as_str()).is_some())
            })
            .collect();
        json!({"description": tool.definition.description, "affected_fields": fields,
            "input": "[REDACTED:SENSITIVE_INPUT]"})
        .to_string()
    }

    async fn available_tools(&self) -> Result<Vec<AgentTool>, AgentError> {
        Ok(self
            .tools
            .iter()
            .map(|t| AgentTool {
                definition: t.definition.clone(),
                side_effects: t.side_effects,
            })
            .collect())
    }

    async fn call_tool(&self, name: &str, arguments: &str) -> Result<ToolOutcome, AgentError> {
        // HARD allowlist enforcement: only a tool we actually resolved (and thus
        // offered) may be called. This is the empty-allowlist guard and the
        // hallucinated-tool guard, independent of the principal's profile
        // restriction (whose `Some([])` form means *unrestricted*, not deny-all).
        let Some(rt) = self.tools.iter().find(|t| t.model_name == name) else {
            return Ok(ToolOutcome {
                content: format!("tool `{name}` is not in this agent's allowlist"),
                is_error: true,
            });
        };

        let args: Map<String, Value> = if arguments.trim().is_empty() {
            Map::new()
        } else {
            match serde_json::from_str::<Value>(arguments) {
                Ok(Value::Object(m)) => m,
                Ok(_) => {
                    return Ok(ToolOutcome {
                        content: "tool arguments must be a JSON object".to_owned(),
                        is_error: true,
                    });
                }
                Err(e) => {
                    return Ok(ToolOutcome {
                        content: format!("invalid tool arguments JSON: {e}"),
                        is_error: true,
                    });
                }
            }
        };

        // Governed read built-in: dispatch through the assist_read seam,
        // which applies the SAME Cedar overlay + namespace scope floor as a
        // direct MCP call. A denial/failure is fed back to the model (not raised),
        // exactly like the upstream path below.
        if rt.builtin {
            let Some(assist) = self.assist_read.as_ref() else {
                return Ok(ToolOutcome {
                    content: "read built-in access is not configured on this gateway".to_owned(),
                    is_error: true,
                });
            };
            let fq = format!("{}.{}", rt.server, rt.tool);
            return match assist.call(&fq, Some(args), Some(&self.principal)).await {
                Ok(result) => {
                    let v = serde_json::to_value(&result).unwrap_or(Value::Null);
                    Ok(call_result_to_outcome(&v))
                }
                Err(e) => Ok(ToolOutcome {
                    content: format!("tool call denied or failed: {e}"),
                    is_error: true,
                }),
            };
        }

        let mut req = InvocationRequest::new(rt.server.clone(), rt.tool.clone())
            .with_arguments(Some(args))
            .with_acting_agent(self.acting_agent.clone());
        // Pin the contract whose side-effect fact drove the operator-approval
        // decision at listing time. If a reload changed the contract since then
        // (e.g. read-only to side-effecting), the pipeline refuses at the
        // resolve stage instead of executing a mutation the operator never
        // confirmed — which matters most for group-governed servers that carry
        // no persistent approval-grant backstop.
        if let Some(expected) = rt.expected_contract.clone() {
            req = req.with_expected_contract(expected);
        }

        match self.invocation.invoke(Some(&self.principal), req).await {
            // Serialize the result generically (this crate never names the
            // `rmcp` wire type in production — mirrors the dashboard try-it
            // path) and read text out of its JSON shape.
            Ok(InvocationResponse::Unary(result)) => {
                let v = serde_json::to_value(&result).unwrap_or(Value::Null);
                Ok(call_result_to_outcome(&v))
            }
            Ok(InvocationResponse::UnaryValue(v)) => Ok(ToolOutcome {
                content: v.to_string(),
                is_error: false,
            }),
            Ok(InvocationResponse::Stream(_)) => Ok(ToolOutcome {
                content: "tool returned an unexpected streaming response".to_owned(),
                is_error: true,
            }),
            // The runtime declares no input capabilities, so the pipeline
            // fails an MRTR pause closed before it can surface here; treat a
            // stray one as an (error) tool result the model can adapt to.
            Ok(InvocationResponse::InputRequired(_)) => Ok(ToolOutcome {
                content: "tool paused for interactive input this agent cannot provide".to_owned(),
                is_error: true,
            }),
            // A pipeline denial (Cedar / profile / step-up / budget) or upstream
            // failure is fed back to the model as an (error) tool result so it
            // can adapt — NOT a hard loop error.
            Err(e) => Ok(ToolOutcome {
                content: format!("tool call denied or failed: {e}"),
                is_error: true,
            }),
        }
    }
}

/// Flatten a serialized MCP `CallToolResult` (its rmcp wire JSON) to the text
/// fed back to the model. The caller serializes the result generically so this
/// crate never names the `rmcp` wire type in production (mirrors the dashboard
/// try-it path). Prefer an explicit text rendering: some tools intentionally
/// keep sensitive machine fields out of that model-facing representation.
/// Structured-only results remain usable, and a compatibility copy is never
/// appended. Error status is independent of the representation selected.
fn call_result_to_outcome(v: &Value) -> ToolOutcome {
    let is_error = v.get("isError").and_then(Value::as_bool).unwrap_or(false);
    let mut text = String::new();
    if let Some(parts) = v.get("content").and_then(Value::as_array) {
        for part in parts {
            if part.get("type").and_then(Value::as_str) == Some("text") {
                if let Some(t) = part.get("text").and_then(Value::as_str) {
                    text.push_str(t);
                }
            }
        }
    }
    let content = if text.is_empty() {
        v.get("structuredContent")
            .filter(|value| !value.is_null())
            .or_else(|| v.get("content"))
            .map(|c| c.to_string())
            .unwrap_or_else(|| "(empty tool result)".to_owned())
    } else {
        text
    };
    ToolOutcome { content, is_error }
}

// ---------------------------------------------------------------------------
// Approval seam — in-chat side-effects confirmation
// ---------------------------------------------------------------------------

/// Default wait for an operator's approve/reject before a side-effecting call is
/// auto-rejected. Long enough for a human to react; bounded so a parked call
/// can't hold the chat's SSE stream + loop task open indefinitely.
pub const APPROVAL_TIMEOUT: Duration = Duration::from_secs(300);

/// The real [`ApprovalGate`]: parks a side-effecting call in the
/// [`ChatApprovalRegistry`](crate::chat_approvals::ChatApprovalRegistry) and
/// blocks until the operator resolves it via `POST /agent_chat/approve` (or the
/// timeout fires, which rejects). Bound to the chat session + its owning
/// principal, so only that operator's decision applies.
pub struct ChatApprovalGate {
    registry: SharedChatApprovals,
    session_id: Uuid,
    tenant: String,
    user_sub: String,
    timeout: Duration,
}

impl ChatApprovalGate {
    pub fn new(
        registry: SharedChatApprovals,
        session_id: Uuid,
        tenant: impl Into<String>,
        user_sub: impl Into<String>,
    ) -> Self {
        Self {
            registry,
            session_id,
            tenant: tenant.into(),
            user_sub: user_sub.into(),
            timeout: APPROVAL_TIMEOUT,
        }
    }

    /// Override the approval timeout (tests use a short one).
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

#[async_trait]
impl ApprovalGate for ChatApprovalGate {
    async fn authorize(&self, call: &AgentToolCall) -> ApprovalDecision {
        // Register the slot BEFORE awaiting, so a fast operator decision can't
        // race ahead of registration (no read-await-write window).
        let rx = self
            .registry
            .register(self.session_id, &call.id, &self.tenant, &self.user_sub);
        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(decision)) => decision,
            // Sender dropped without a decision (slot cancelled) — reject so the
            // loop never hangs.
            Ok(Err(_)) => ApprovalDecision::Rejected("approval was cancelled".to_owned()),
            Err(_) => {
                self.registry.cancel(self.session_id, &call.id);
                ApprovalDecision::Rejected("approval timed out — no operator response".to_owned())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Effective principal
// ---------------------------------------------------------------------------

/// Build the agent's effective principal: the human session principal with its
/// call-restrictions narrowed to the agent's tool allowlist **plus its own
/// model**. **Never broadens** — see [`narrow_restrictions`].
///
/// `model_alias` MUST be included: the agent's model call dispatches as this same
/// principal under `("llm", <alias>)`, so a restriction that listed only the tool
/// servers would block the agent's own model (`evaluate_profile_restrictions`
/// would reject `"llm"`). The narrowing therefore always permits `llm` +
/// `llm.<alias>` alongside the tool allowlist.
pub fn effective_principal(
    human: &Principal,
    allowed_tools: &[String],
    model_alias: &str,
) -> Principal {
    let mut p = human.clone();
    p.api_key_profile_restrictions = narrow_restrictions(
        human.api_key_profile_restrictions.as_ref(),
        allowed_tools,
        model_alias,
    );
    p
}

/// Compute the effective call-restriction for an agent.
///
/// Safety contract — this must only ever *tighten*:
/// - If the human has a non-empty server or tool restriction, leave it
///   untouched. The agent allowlist is enforced on top by `available_tools` +
///   `call_tool`; rewriting the human's restriction here risks broadening it.
/// - If the human is **unrestricted**, pin the restriction to the agent's
///   operational surface: its model (`llm` / `llm.<alias>`) plus its tool
///   allowlist (servers derived from the fq tool names). Pure tightening — the
///   model is permitted because the agent must be able to call it; everything
///   else is denied. A profile with empty lists keeps its identity while gaining
///   these agent limits. (An empty tool allowlist ⇒ a model-only principal.)
fn narrow_restrictions(
    existing: Option<&ApiKeyProfileRestrictions>,
    allowed_tools: &[String],
    model_alias: &str,
) -> Option<ApiKeyProfileRestrictions> {
    if let Some(r) = existing.filter(|restriction| {
        restriction
            .allowed_servers
            .as_ref()
            .is_some_and(|servers| !servers.is_empty())
            || restriction
                .allowed_tools
                .as_ref()
                .is_some_and(|tools| !tools.is_empty())
    }) {
        return Some(r.clone());
    }
    // The model is always part of the agent's surface (its own model call routes
    // as `("llm", <alias>)`), so include it even when the tool allowlist is empty.
    let model_fq = format!("{LLM_SERVER}.{model_alias}");
    let mut servers: Vec<String> = allowed_tools
        .iter()
        .filter_map(|fq| fq.split_once('.').map(|(s, _)| s.to_owned()))
        .collect();
    servers.push(LLM_SERVER.to_owned());
    servers.sort();
    servers.dedup();
    let mut tools: Vec<String> = allowed_tools.to_vec();
    tools.push(model_fq);
    let (profile_id, profile_name) = existing.map_or_else(
        || ("gateway-agent".to_owned(), "agent-allowlist".to_owned()),
        |restriction| {
            (
                restriction.profile_id.clone(),
                restriction.profile_name.clone(),
            )
        },
    );
    Some(ApiKeyProfileRestrictions {
        profile_id,
        profile_name,
        allowed_servers: Some(servers),
        allowed_tools: Some(tools),
    })
}

/// Sanitize a fully-qualified `server.tool` into a model-facing function name
/// (`^[A-Za-z0-9_-]{1,64}$`), disambiguating collisions against `taken`.
fn sanitize_tool_name(fq: &str, taken: &mut HashSet<String>) -> String {
    let mut s: String = fq
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if s.len() > MAX_TOOL_NAME_LEN {
        s.truncate(MAX_TOOL_NAME_LEN);
    }
    if s.is_empty() {
        s.push('_');
    }
    if taken.contains(&s) {
        let base: String = s.chars().take(MAX_TOOL_NAME_LEN - 4).collect();
        for i in 1.. {
            let cand = format!("{base}_{i}");
            if !taken.contains(&cand) {
                s = cand;
                break;
            }
        }
    }
    taken.insert(s.clone());
    s
}

#[cfg(test)]
mod tests {

    #[test]
    fn structured_tool_results_have_one_authoritative_representation() {
        let payload = serde_json::json!({"contents": "synthetic-content", "complete": true});
        for compatibility in [
            serde_json::json!([]),
            serde_json::json!([
                {"type": "text", "text": payload.to_string()}
            ]),
        ] {
            for is_error in [false, true] {
                let outcome = super::call_result_to_outcome(&serde_json::json!({
                    "structuredContent": payload, "content": compatibility, "isError": is_error
                }));
                assert_eq!(outcome.content, payload.to_string());
                assert_eq!(outcome.is_error, is_error);
            }
        }
        let protected = super::call_result_to_outcome(&serde_json::json!({
            "structuredContent": {"synthetic_private_value": "not-model-content"},
            "content": [{"type": "text", "text": "Capture the machine result in the trusted runtime."}]
        }));
        assert_eq!(
            protected.content,
            "Capture the machine result in the trusted runtime."
        );
        assert!(!protected.content.contains("not-model-content"));
        let legacy = super::call_result_to_outcome(&serde_json::json!({
            "content": [{"type":"text", "text":"legacy"}, {"type":"text", "text":" result"}]
        }));
        assert_eq!(legacy.content, "legacy result");
        assert!(!legacy.is_error);
    }
    use super::*;
    use crate::chat_approvals::ChatApprovalRegistry;
    use rmcp::model::{CallToolResult, ContentBlock as Content};
    use std::sync::Arc;
    use std::sync::Mutex;
    use waygate_agent::ApprovalGate;
    use waygate_core::TenantId;
    use waygate_oidc::AuthMethod;

    fn agent_call(id: &str) -> AgentToolCall {
        AgentToolCall {
            id: id.to_owned(),
            name: "example_messages__send".to_owned(),
            arguments: "{}".to_owned(),
        }
    }

    #[tokio::test]
    async fn approval_gate_returns_operator_decision() {
        let registry: SharedChatApprovals = Arc::new(ChatApprovalRegistry::new());
        let session = Uuid::new_v4();
        let gate = ChatApprovalGate::new(registry.clone(), session, "t1", "alice");
        // Resolve from another task once the gate has parked the call.
        let r2 = registry.clone();
        let approver = tokio::spawn(async move {
            // Spin until the slot is registered, then approve.
            loop {
                if r2.resolve(session, "c1", "t1", "alice", ApprovalDecision::Approved) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        });
        let decision = gate.authorize(&agent_call("c1")).await;
        approver.await.unwrap();
        assert_eq!(decision, ApprovalDecision::Approved);
    }

    #[tokio::test]
    async fn approval_gate_times_out_to_rejected() {
        let registry: SharedChatApprovals = Arc::new(ChatApprovalRegistry::new());
        let gate = ChatApprovalGate::new(registry, Uuid::new_v4(), "t1", "alice")
            .with_timeout(Duration::from_millis(20));
        let decision = gate.authorize(&agent_call("c1")).await;
        assert!(matches!(decision, ApprovalDecision::Rejected(r) if r.contains("timed out")));
    }

    fn principal(sub: &str) -> Principal {
        Principal {
            sub: sub.to_owned(),
            email: None,
            groups: vec![],
            issuer: "test".to_owned(),
            scopes: vec![],
            tenant: TenantId::default(),
            auth_method: AuthMethod::Oauth,
            raw_token: None,
            scim: None,
            enrichment_blocked: None,
            roles: vec![],
            api_key_profile_restrictions: None,
        }
    }

    /// What a [`FakeInvocation`] returns. Stored as the raw pieces (not an
    /// [`InvocationResponse`], whose `Stream` variant is `!Sync` and would make
    /// the fake `!Sync`, violating the `InvocationService: Sync` bound).
    enum Canned {
        Value(Value),
        Result(CallToolResult),
    }

    /// A scripted [`InvocationService`] that records the last request and returns
    /// a canned response.
    struct FakeInvocation {
        canned: Canned,
        last: Mutex<Option<InvocationRequest>>,
    }

    impl FakeInvocation {
        fn unary_value(v: Value) -> Arc<Self> {
            Arc::new(Self {
                canned: Canned::Value(v),
                last: Mutex::new(None),
            })
        }
        fn unary(result: CallToolResult) -> Arc<Self> {
            Arc::new(Self {
                canned: Canned::Result(result),
                last: Mutex::new(None),
            })
        }
    }

    #[async_trait]
    impl waygate_invocation::InvocationService for FakeInvocation {
        async fn invoke(
            &self,
            _principal: Option<&Principal>,
            req: InvocationRequest,
        ) -> Result<InvocationResponse, waygate_invocation::InvocationError> {
            *self.last.lock().unwrap() = Some(req);
            Ok(match &self.canned {
                Canned::Value(v) => InvocationResponse::UnaryValue(v.clone()),
                Canned::Result(c) => InvocationResponse::Unary(c.clone()),
            })
        }
    }

    fn dispatch_with(tools: Vec<ResolvedTool>, inv: SharedInvocation) -> UpstreamAgentDispatch {
        UpstreamAgentDispatch {
            invocation: inv,
            assist_read: None,
            principal: principal("alice"),
            acting_agent: "agent:test".to_owned(),
            tools,
        }
    }

    fn resolved(model_name: &str, server: &str, tool: &str, side_effects: bool) -> ResolvedTool {
        ResolvedTool {
            sensitive_input: false,
            model_name: model_name.to_owned(),
            server: server.to_owned(),
            tool: tool.to_owned(),
            side_effects,
            expected_contract: None,
            definition: CanonicalTool {
                name: model_name.to_owned(),
                description: None,
                parameters: json!({"type": "object"}),
                strict: None,
            },
            builtin: false,
        }
    }

    /// A minimal resolved contract identity for pinning tests. The specific
    /// field values are irrelevant to the forwarding assertion; only that the
    /// SAME identity reaches the invocation request unchanged.
    fn sample_contract(side_effects: bool) -> InvocationContractIdentity {
        InvocationContractIdentity {
            authority: waygate_invocation::InvocationContractAuthority::ManifestFallback {
                approval_requirements_known: true,
                approved_behavior_hash: None,
            },
            input_schema_hash: None,
            output_schema_hash: None,
            tool_annotations_hash: None,
            action_metadata_hash: None,
            operations_hash: None,
            risk: waygate_invocation::InvocationRisk::Low,
            side_effects,
            pii: false,
            requires_approval: false,
            requires_approval_known: true,
        }
    }

    /// A fake governed read-built-in seam: advertises one read tool and records
    /// the last call. `call` succeeds (the governance under test lives in the
    /// real `GovernedObserveCaller`; here we exercise the agent's dispatch wiring).
    struct FakeAssistRead {
        last: Mutex<Option<String>>,
    }

    #[async_trait]
    impl waygate_mcp::AssistReadTools for FakeAssistRead {
        async fn read_tools(
            &self,
            _principal: Option<&Principal>,
        ) -> Vec<waygate_mcp::AssistReadTool> {
            vec![waygate_mcp::AssistReadTool {
                name: "gateway-observe.query_audit".to_owned(),
                description: "read the audit log".to_owned(),
                input_schema: serde_json::Map::new(),
                side_effects: false,
            }]
        }
        async fn call(
            &self,
            name: &str,
            _arguments: Option<rmcp::model::JsonObject>,
            _principal: Option<&Principal>,
        ) -> Result<CallToolResult, rmcp::ErrorData> {
            *self.last.lock().unwrap() = Some(name.to_owned());
            Ok(CallToolResult::success(vec![Content::text("audit rows")]))
        }
    }

    #[tokio::test]
    async fn resolve_offers_read_builtin_and_dispatches_via_assist_seam() {
        // An allowlisted gateway-observe.* tool resolves through the assist_read
        // seam: it's offered to the model, and a call routes to the seam
        // (NOT the upstream invocation pipeline).
        let inv = FakeInvocation::unary(CallToolResult::success(vec![Content::text("UPSTREAM")]));
        let assist: SharedAssistReadTools = Arc::new(FakeAssistRead {
            last: Mutex::new(None),
        });
        let pool = UpstreamPool::connect(std::collections::BTreeMap::new()).await;
        let d = UpstreamAgentDispatch::resolve(
            inv.clone(),
            &pool,
            Some(assist.clone()),
            principal("alice"),
            "agent:test",
            &["gateway-observe.query_audit".to_owned()],
        )
        .await;

        let offered = d.available_tools().await.expect("tools");
        assert_eq!(offered.len(), 1, "the read built-in should be offered");
        assert!(
            !offered[0].side_effects,
            "observe reads are not side-effecting"
        );

        let out = d
            .call_tool(&offered[0].definition.name, "{}")
            .await
            .expect("outcome");
        assert!(!out.is_error);
        assert_eq!(out.content, "audit rows");
        // It went through the assist seam, never the upstream pipeline.
        assert!(
            inv.last.lock().unwrap().is_none(),
            "a built-in call must not reach the invocation pipeline"
        );
    }

    #[tokio::test]
    async fn resolve_skips_builtins_without_the_assist_seam() {
        // No assist_read wired ⇒ a gateway-observe.* allowlist entry is not
        // resolved (not offered, not callable) — the agent stays upstream-only.
        let inv = FakeInvocation::unary(CallToolResult::success(vec![Content::text("x")]));
        let pool = UpstreamPool::connect(std::collections::BTreeMap::new()).await;
        let d = UpstreamAgentDispatch::resolve(
            inv,
            &pool,
            None,
            principal("alice"),
            "agent:test",
            &["gateway-observe.query_audit".to_owned()],
        )
        .await;
        assert!(d.available_tools().await.expect("tools").is_empty());
    }

    #[tokio::test]
    async fn resolve_never_offers_mutating_builtins_to_the_agent() {
        // Even with the seam wired, a non-read built-in namespace (propose/control)
        // is never resolved — the fake only advertises the observe read tool.
        let inv = FakeInvocation::unary(CallToolResult::success(vec![Content::text("x")]));
        let assist: SharedAssistReadTools = Arc::new(FakeAssistRead {
            last: Mutex::new(None),
        });
        let pool = UpstreamPool::connect(std::collections::BTreeMap::new()).await;
        let d = UpstreamAgentDispatch::resolve(
            inv,
            &pool,
            Some(assist),
            principal("alice"),
            "agent:test",
            &["gateway-admin.propose_change".to_owned()],
        )
        .await;
        assert!(
            d.available_tools().await.expect("tools").is_empty(),
            "mutating built-ins must never be offered to the chat agent"
        );
    }

    #[tokio::test]
    async fn model_folds_text_and_tool_calls_and_stamps_acting_agent() {
        let body = json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "let me check",
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": { "name": "example_messages__send", "arguments": "{\"to\":\"x\"}" }
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": { "prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15 }
        });
        let inv = FakeInvocation::unary_value(body);
        let model = OpenAiAgentModel::new(
            inv.clone(),
            principal("alice"),
            "gpt-x",
            "agent:helper",
            Some(0.2),
        );
        let turn = model
            .complete(
                &[CanonicalMessage {
                    role: Role::User,
                    content: vec![ContentPart::Text {
                        text: "hi".to_owned(),
                    }],
                }],
                &[],
            )
            .await
            .expect("complete");

        assert_eq!(turn.text(), "let me check");
        assert_eq!(turn.tool_calls.len(), 1);
        assert_eq!(turn.tool_calls[0].id, "call_1");
        assert_eq!(turn.tool_calls[0].name, "example_messages__send");
        assert_eq!(turn.usage_tokens, 15);
        // The assistant message carries the text + the tool-use part.
        assert!(turn
            .assistant
            .content
            .iter()
            .any(|p| matches!(p, ContentPart::ToolUse { .. })));

        // The model call was stamped for agent attribution + sent non-streaming.
        let req = inv.last.lock().unwrap().clone().expect("a request");
        assert_eq!(req.acting_agent(), Some("agent:helper"));
    }

    #[tokio::test]
    async fn model_surfaces_error_body() {
        let inv = FakeInvocation::unary_value(json!({ "error": { "message": "rate limited" } }));
        let model = OpenAiAgentModel::new(inv, principal("a"), "m", "agent:x", None);
        let err = model.complete(&[], &[]).await.unwrap_err();
        assert!(matches!(err, AgentError::Model(m) if m.contains("rate limited")));
    }

    #[test]
    fn chat_approval_preview_hides_sensitive_values_but_keeps_consequences() {
        let mut tool = resolved("compose_write", "example-operations", "compose.write", true);
        tool.sensitive_input = true;
        tool.definition.description = Some(
            "Replace inline configuration; upstream retention applies; deploy separately."
                .to_owned(),
        );
        tool.definition.parameters = json!({"type": "object", "properties": {
            "selector": {"type": "string"}, "contents": {"type": "string"}
        }});
        let dispatch = dispatch_with(
            vec![tool],
            FakeInvocation::unary(CallToolResult::success(vec![])),
        );
        let arguments = json!({"selector": "private-target", "contents": "opaque-secret",
            "untrusted-key": "value"})
        .to_string();
        let preview = dispatch.approval_preview("compose_write", &arguments);
        let view: Value = serde_json::from_str(&preview).unwrap();
        let mut fields: Vec<_> = view["affected_fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|field| field.as_str().unwrap())
            .collect();
        fields.sort_unstable();
        assert_eq!(fields, ["contents", "selector"]);
        assert!(view["description"]
            .as_str()
            .unwrap()
            .contains("deploy separately"));
        for hidden in ["private-target", "opaque-secret", "untrusted-key"] {
            assert!(!preview.contains(hidden));
        }
        assert!(!dispatch
            .approval_preview("unavailable", &arguments)
            .contains("opaque-secret"));
    }

    #[tokio::test]
    async fn dispatch_refuses_tool_not_in_allowlist() {
        // Even with a permissive invocation, an unknown model name is refused
        // BEFORE any dispatch (the empty/hallucinated-tool guard).
        let inv = FakeInvocation::unary(CallToolResult::success(vec![Content::text(
            "should not run",
        )]));
        let d = dispatch_with(vec![], inv.clone());
        let out = d.call_tool("anything", "{}").await.expect("outcome");
        assert!(out.is_error);
        assert!(out.content.contains("not in this agent's allowlist"));
        assert!(
            inv.last.lock().unwrap().is_none(),
            "a non-allowlisted call must never reach the pipeline"
        );
    }

    #[tokio::test]
    async fn dispatch_calls_allowlisted_tool_and_maps_result() {
        let inv = FakeInvocation::unary(CallToolResult::success(vec![Content::text("pong")]));
        let d = dispatch_with(
            vec![resolved(
                "example_messages__ping",
                "example-messages",
                "ping",
                false,
            )],
            inv.clone(),
        );
        let out = d
            .call_tool("example_messages__ping", "{\"x\":1}")
            .await
            .expect("outcome");
        assert!(!out.is_error);
        assert_eq!(out.content, "pong");
        // It dispatched to the fully-qualified (server, tool), stamped as agent.
        let req = inv.last.lock().unwrap().clone().expect("a request");
        assert_eq!(req.acting_agent(), Some("agent:test"));
    }

    #[tokio::test]
    async fn dispatch_pins_the_listing_time_contract() {
        // A tool whose contract was resolved at listing time must have that
        // identity PINNED into the invocation, so the pipeline refuses if the
        // contract drifts (e.g. read-only to side-effecting) between the
        // operator-approval decision and execution. Built-ins and unresolved
        // tools carry no identity and are not pinned.
        let pinned = sample_contract(false);
        let mut rt = resolved("example_messages__ping", "example-messages", "ping", false);
        rt.expected_contract = Some(pinned.clone());
        let inv = FakeInvocation::unary(CallToolResult::success(vec![Content::text("pong")]));
        let d = dispatch_with(vec![rt], inv.clone());
        let out = d
            .call_tool("example_messages__ping", "{}")
            .await
            .expect("outcome");
        assert!(!out.is_error);
        let req = inv.last.lock().unwrap().clone().expect("a request");
        assert_eq!(
            req.expected_contract.as_ref(),
            Some(&pinned),
            "call_tool must pin the listing-time contract identity into the invocation",
        );
    }

    #[tokio::test]
    async fn dispatch_does_not_pin_when_no_contract_resolved() {
        // A tool with no resolved identity (unresolved/quarantined at listing,
        // or a built-in) must NOT pin a contract — pinning `None` would be
        // meaningless and the pipeline resolves and gates it directly.
        let inv = FakeInvocation::unary(CallToolResult::success(vec![Content::text("pong")]));
        let d = dispatch_with(
            vec![resolved(
                "example_messages__ping",
                "example-messages",
                "ping",
                false,
            )],
            inv.clone(),
        );
        let _ = d
            .call_tool("example_messages__ping", "{}")
            .await
            .expect("outcome");
        let req = inv.last.lock().unwrap().clone().expect("a request");
        assert!(
            req.expected_contract.is_none(),
            "an unpinned tool must not carry an expected contract",
        );
    }

    #[tokio::test]
    async fn dispatch_maps_invalid_arguments_to_error_outcome() {
        let inv = FakeInvocation::unary(CallToolResult::success(vec![Content::text("x")]));
        let d = dispatch_with(
            vec![resolved(
                "example_messages__ping",
                "example-messages",
                "ping",
                false,
            )],
            inv.clone(),
        );
        let out = d
            .call_tool("example_messages__ping", "not json")
            .await
            .expect("outcome");
        assert!(out.is_error);
        assert!(out.content.contains("invalid tool arguments"));
        assert!(
            inv.last.lock().unwrap().is_none(),
            "bad args never dispatch"
        );
    }

    #[test]
    fn narrow_restrictions_includes_model_and_tools_for_unrestricted_human() {
        let r = narrow_restrictions(
            None,
            &[
                "example-messages.send".to_owned(),
                "example-messages.read".to_owned(),
            ],
            "gpt-x",
        )
        .expect("restriction");
        // Servers cover the tools' servers AND the model's `llm` namespace
        // (sorted + deduped).
        assert_eq!(
            r.allowed_servers.as_deref(),
            Some(&["example-messages".to_owned(), "llm".to_owned()][..])
        );
        let tools = r.allowed_tools.expect("tools");
        assert!(tools.contains(&"example-messages.send".to_owned()));
        assert!(tools.contains(&"example-messages.read".to_owned()));
        // The agent's own model MUST be permitted — else the model call (which
        // dispatches as this principal under `("llm", alias)`) would be blocked.
        assert!(
            tools.contains(&"llm.gpt-x".to_owned()),
            "model must be permitted"
        );
    }

    #[test]
    fn narrow_restrictions_empty_allowlist_is_model_only() {
        // An empty tool allowlist still needs the model permitted, so the
        // restriction is model-only (NOT `None`/unrestricted, NOT deny-all).
        let r = narrow_restrictions(None, &[], "gpt-x").expect("model-only restriction");
        assert_eq!(r.allowed_servers.as_deref(), Some(&["llm".to_owned()][..]));
        assert_eq!(
            r.allowed_tools.as_deref(),
            Some(&["llm.gpt-x".to_owned()][..])
        );
    }

    #[test]
    fn narrow_restrictions_never_broadens_a_restricted_human() {
        // A human already confined to `example-observability` must NOT be widened by an agent
        // whose allowlist names a different server — the human's restriction is
        // preserved verbatim (the agent allowlist is enforced separately).
        let human = ApiKeyProfileRestrictions {
            profile_id: "p".to_owned(),
            profile_name: "confined".to_owned(),
            allowed_servers: Some(vec!["example-observability".to_owned()]),
            allowed_tools: None,
        };
        let r = narrow_restrictions(Some(&human), &["example-messages.send".to_owned()], "gpt-x")
            .expect("kept");
        assert_eq!(
            r.allowed_servers.as_deref(),
            Some(&["example-observability".to_owned()][..])
        );
        assert!(r.allowed_tools.is_none());
    }

    #[test]
    fn narrow_restrictions_keeps_empty_profile_identity_and_adds_agent_limits() {
        let human = ApiKeyProfileRestrictions {
            profile_id: "minting-profile".to_owned(),
            profile_name: "minting only".to_owned(),
            allowed_servers: Some(Vec::new()),
            allowed_tools: Some(Vec::new()),
        };
        let r = narrow_restrictions(Some(&human), &["example-messages.send".to_owned()], "gpt-x")
            .expect("agent restriction");
        assert_eq!(r.profile_id, "minting-profile");
        assert_eq!(r.profile_name, "minting only");
        assert_eq!(
            r.allowed_servers.as_deref(),
            Some(&["example-messages".to_owned(), "llm".to_owned()][..])
        );
        assert_eq!(
            r.allowed_tools.as_deref(),
            Some(&["example-messages.send".to_owned(), "llm.gpt-x".to_owned()][..])
        );
    }

    #[test]
    fn sanitize_tool_name_encodes_and_disambiguates() {
        let mut taken = HashSet::new();
        assert_eq!(
            sanitize_tool_name("example-messages.send", &mut taken),
            "example-messages_send"
        );
        // A second fq that sanitizes to the same label is disambiguated.
        assert_eq!(
            sanitize_tool_name("example-messages/send", &mut taken),
            "example-messages_send_1"
        );
    }

    #[test]
    fn canonical_messages_render_tool_roundtrip() {
        let msgs = vec![
            CanonicalMessage {
                role: Role::Assistant,
                content: vec![ContentPart::ToolUse {
                    id: "c1".to_owned(),
                    name: "t".to_owned(),
                    arguments: "{}".to_owned(),
                }],
            },
            CanonicalMessage {
                role: Role::Tool,
                content: vec![ContentPart::ToolResult {
                    tool_call_id: "c1".to_owned(),
                    content: "ok".to_owned(),
                }],
            },
        ];
        let rendered = canonical_messages_to_openai(&msgs);
        assert_eq!(rendered.len(), 2);
        assert_eq!(rendered[0]["role"], "assistant");
        assert_eq!(rendered[0]["tool_calls"][0]["id"], "c1");
        assert_eq!(rendered[1]["role"], "tool");
        assert_eq!(rendered[1]["tool_call_id"], "c1");
        assert_eq!(rendered[1]["content"], "ok");
    }
}
