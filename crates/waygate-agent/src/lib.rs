//! The in-process agentic loop and its trait seams.
//!
//! This crate owns the bounded LLM ↔ tool loop that drives the in-app agents
//! (the interactive chat agent first; policy-review / classification task
//! agents later). It is deliberately **decoupled** from the inference
//! dispatcher, the governed tool-invocation pipeline, and the dashboard: the
//! loop talks to three trait seams; the real implementations live in
//! `waygate-agent-runtime`:
//!
//! - [`AgentModel`] — one unary model turn (build → dispatch → fold) reduced to
//!   a [`ModelTurn`]. The real impl wraps `waygate_llm_dispatch::LlmDispatcher`;
//!   tests supply a scripted fake.
//! - [`AgentToolDispatch`] — the agent's tool surface + governed execution. The
//!   real impl routes through `SharedInvocation` (upstream) and the built-in
//!   namespaces, bound to the agent's effective principal (the human + the
//!   agent's tool allowlist as `api_key_profile_restrictions`), so every call
//!   inherits Cedar authz + audit. Tests supply an in-memory fake.
//! - [`ApprovalGate`] — the per-call confirmation for **side-effecting** tools.
//!   The real impl (`ChatApprovalGate` in `waygate-agent-runtime`) blocks on
//!   the operator's in-chat confirm via the data-plane HITL machinery; tests
//!   auto-decide.
//!
//! Plus [`AgentEventSink`] for streaming step events to a UI (mapped to SSE
//! frames by the chat handler).
//!
//! The loop itself ([`run::run_agent`]) and the system-prompt assembler
//! ([`prompt::build_system_prompt`]) are pure and fully unit-tested here with
//! fakes — no network, no DB.
//!
//! ## Safety properties enforced by the loop
//!
//! - **Bounded.** Every run is capped by `max_steps`, `max_tool_calls`, and an
//!   optional `token_budget`; a runaway agent stops with a [`StopReason`]
//!   rather than spinning or burning budget without limit.
//! - **Side-effects gate.** A tool whose facts mark it side-effecting is never
//!   executed without [`ApprovalGate`] approval; an unknown tool is treated as
//!   side-effecting (fail-safe). A rejected call is fed back to the model as a
//!   tool result, never silently retried.
//! - **Prompt-injection posture.** The assembled system prompt instructs the
//!   model to treat tool output as data, not instructions — the loop never
//!   elevates retrieved content to control.

use async_trait::async_trait;
use waygate_llm_translate::{CanonicalMessage, CanonicalTool, ContentPart};

pub mod prompt;
pub mod run;

pub use prompt::{build_system_prompt, SystemPromptContext};
pub use run::{run_agent, AgentOutcome, AgentRunConfig, StopReason};

/// A tool call the model wants executed this turn. `id` correlates the
/// assistant's `ToolUse` with the `ToolResult` fed back (the same string flows
/// `ToolUse.id` → `ToolResult.tool_call_id`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AgentToolCall {
    pub id: String,
    pub name: String,
    /// Raw JSON arguments string the model emitted (kept verbatim).
    pub arguments: String,
}

/// The model's output for one turn, reduced from a canonical response.
#[derive(Debug, Clone)]
pub struct ModelTurn {
    /// The assistant message to append to the transcript — text parts plus any
    /// tool-use parts, in canonical form.
    pub assistant: CanonicalMessage,
    /// The tool calls to execute this turn (mirrors the `ToolUse` parts in
    /// [`Self::assistant`]). Empty ⇒ [`Self::assistant`] is the final answer.
    pub tool_calls: Vec<AgentToolCall>,
    /// Total tokens consumed by this turn (input + output), summed by the
    /// model impl from the canonical usage. Drives the optional budget cap;
    /// a single total is all the per-run `token_budget` needs.
    pub usage_tokens: u64,
}

impl ModelTurn {
    /// Concatenated assistant text — the final answer when [`Self::tool_calls`]
    /// is empty.
    pub fn text(&self) -> String {
        self.assistant
            .content
            .iter()
            .filter_map(|p| match p {
                ContentPart::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("")
    }
}

/// One model turn: the LLM-call seam. The real impl builds an `LlmRequest` from
/// the running transcript + tools, dispatches it unary, folds the response, and
/// reduces it to a [`ModelTurn`].
#[async_trait]
pub trait AgentModel: Send + Sync {
    async fn complete(
        &self,
        messages: &[CanonicalMessage],
        tools: &[CanonicalTool],
    ) -> Result<ModelTurn, AgentError>;
}

/// A tool offered to the agent: its model-facing definition plus the
/// `side_effects` fact that drives the approval gate.
#[derive(Debug, Clone)]
pub struct AgentTool {
    pub definition: CanonicalTool,
    /// `true` ⇒ executing this tool mutates external state, so the loop must
    /// get [`ApprovalGate`] approval before running it.
    pub side_effects: bool,
}

/// The result of executing one tool call.
#[derive(Debug, Clone)]
pub struct ToolOutcome {
    /// Result text fed back to the model as a `ToolResult`.
    pub content: String,
    /// `true` ⇒ the call failed; the model is told so it can adapt.
    pub is_error: bool,
}

/// The agent's tool surface + governed execution, pre-bound to the agent's
/// effective principal. The real impl applies the allowlist (via the
/// principal's `api_key_profile_restrictions`) and routes through the gateway's
/// governed invocation path, so every call is authorized + audited identically
/// to an external MCP client. `available_tools` returns only the tools the
/// agent is allowed to call.
#[async_trait]
pub trait AgentToolDispatch: Send + Sync {
    async fn available_tools(&self) -> Result<Vec<AgentTool>, AgentError>;
    async fn call_tool(&self, name: &str, arguments: &str) -> Result<ToolOutcome, AgentError>;
}

/// The per-call confirmation for side-effecting tools. The real impl
/// surfaces the call to the operator in the chat and blocks on their decision
/// via the data-plane HITL machinery; a rejection (including a timeout) returns
/// [`ApprovalDecision::Rejected`].
#[async_trait]
pub trait ApprovalGate: Send + Sync {
    async fn authorize(&self, call: &AgentToolCall) -> ApprovalDecision;
}

/// An always-approve gate — for non-side-effecting flows and tests that don't
/// exercise the gate. NOT for production side-effecting use.
pub struct AllowAllApproval;

#[async_trait]
impl ApprovalGate for AllowAllApproval {
    async fn authorize(&self, _call: &AgentToolCall) -> ApprovalDecision {
        ApprovalDecision::Approved
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approved,
    /// Declined; the string is an operator-safe reason fed back to the model as
    /// the (error) tool result so it can adapt rather than silently retry.
    Rejected(String),
}

/// Structured step events the loop emits as it runs, for streaming to a UI. The
/// chat handler maps these to SSE frames; tests collect them.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AgentEvent {
    /// Assistant prose produced this turn (may accompany tool calls).
    AssistantText { text: String },
    /// The agent is about to (attempt to) call a tool.
    ToolCall { name: String, arguments: String },
    /// A side-effecting tool is paused pending the operator's confirmation.
    /// `id` mirrors [`AgentToolCall::id`] so a UI can correlate the operator's
    /// approve/reject decision back to this exact call.
    ApprovalRequested {
        id: String,
        name: String,
        arguments: String,
    },
    /// The operator declined a side-effecting tool call.
    ApprovalRejected { name: String, reason: String },
    /// A tool finished (or failed); `content` is the observation.
    ToolResult {
        name: String,
        content: String,
        is_error: bool,
    },
}

/// Sink the loop emits [`AgentEvent`]s to. Kept object-safe + `&mut` so a
/// handler can stream frames or a test can collect into a `Vec`.
pub trait AgentEventSink: Send {
    fn emit(&mut self, event: AgentEvent);
}

/// A no-op sink for callers that don't stream.
pub struct NullEventSink;

impl AgentEventSink for NullEventSink {
    fn emit(&mut self, _event: AgentEvent) {}
}

/// A collecting sink for tests + non-streaming callers.
#[derive(Default)]
pub struct VecEventSink {
    pub events: Vec<AgentEvent>,
}

impl AgentEventSink for VecEventSink {
    fn emit(&mut self, event: AgentEvent) {
        self.events.push(event);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("agent model call failed: {0}")]
    Model(String),
    #[error("agent tool dispatch failed: {0}")]
    Dispatch(String),
}
