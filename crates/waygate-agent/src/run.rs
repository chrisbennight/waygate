//! The bounded agent loop.
//!
//! Alternates model turns and governed tool calls until the model returns a
//! final answer or a bound is hit. Side-effecting tool calls pass through the
//! [`ApprovalGate`] first. See the crate docs for the safety properties.

use std::collections::HashMap;
use waygate_llm_translate::{CanonicalMessage, CanonicalTool, ContentPart, Role};

use crate::{
    AgentError, AgentEvent, AgentEventSink, AgentModel, AgentToolCall, AgentToolDispatch,
    ApprovalDecision, ApprovalGate,
};

/// Per-run bounds. Built by the caller from the agent's `AgentConfig`
/// (`waygate_dashboard_stores::agent_config`) — kept as a plain struct here so this crate stays
/// decoupled from the config store.
#[derive(Debug, Clone)]
pub struct AgentRunConfig {
    /// Max model turns before the loop stops (must be ≥ 1).
    pub max_steps: u32,
    /// Max tool calls across the whole run before the loop stops.
    pub max_tool_calls: u32,
    /// Optional total-token budget for the run; `None` ⇒ no per-run token cap.
    pub token_budget: Option<u64>,
}

/// Why the loop ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// `max_steps` model turns elapsed without a final answer.
    StepCapReached,
    /// `max_tool_calls` reached mid-run.
    ToolCallCapReached,
    /// The accumulated token usage exceeded `token_budget`.
    BudgetExceeded,
}

/// The result of a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentOutcome {
    /// The model produced a final answer.
    Done {
        text: String,
        steps: u32,
        tool_calls: u32,
    },
    /// A bound was hit before a final answer.
    Stopped {
        reason: StopReason,
        steps: u32,
        tool_calls: u32,
    },
}

/// Run the agent loop to completion.
///
/// `transcript` is the running conversation — the caller seeds it with the
/// system message (see [`crate::build_system_prompt`]) plus any history and the
/// new user message; the loop appends assistant + tool-result messages as it
/// goes, so on return it is the full transcript (useful for persistence).
///
/// The available tools come from `dispatch.available_tools()` (already
/// allowlist-filtered by the impl), so the loop never offers the model a tool
/// the agent can't call.
pub async fn run_agent(
    model: &dyn AgentModel,
    dispatch: &dyn AgentToolDispatch,
    approval: &dyn ApprovalGate,
    config: &AgentRunConfig,
    transcript: &mut Vec<CanonicalMessage>,
    events: &mut dyn AgentEventSink,
) -> Result<AgentOutcome, AgentError> {
    let tools = dispatch.available_tools().await?;
    let side_effects: HashMap<String, bool> = tools
        .iter()
        .map(|t| (t.definition.name.clone(), t.side_effects))
        .collect();
    let tool_defs: Vec<CanonicalTool> = tools.into_iter().map(|t| t.definition).collect();

    let mut tool_calls_made: u32 = 0;
    let mut tokens_used: u64 = 0;
    let max_steps = config.max_steps.max(1);

    for step in 1..=max_steps {
        let turn = model.complete(transcript, &tool_defs).await?;

        tokens_used = tokens_used.saturating_add(turn.usage_tokens);

        // The assistant message (text + any tool-use) joins the transcript so
        // the next turn — and any persisted history — sees what the model said.
        transcript.push(turn.assistant.clone());
        let assistant_text = turn.text();
        if !assistant_text.is_empty() {
            events.emit(AgentEvent::AssistantText {
                text: assistant_text.clone(),
            });
        }

        // Budget cap is a HARD invariant: once total usage exceeds the budget
        // we stop, whether this turn is a final answer or wants tools. The
        // answer text (if any) was already appended + streamed above, so a
        // budget stop never hides what the model produced — it only prevents
        // further turns / side effects. A final-answer turn that tips over
        // budget must report BudgetExceeded, not Done, or the cap is soft.
        let over_budget = config
            .token_budget
            .is_some_and(|budget| tokens_used > budget);

        // No tool calls ⇒ this turn is the final answer.
        if turn.tool_calls.is_empty() {
            if over_budget {
                return Ok(AgentOutcome::Stopped {
                    reason: StopReason::BudgetExceeded,
                    steps: step,
                    tool_calls: tool_calls_made,
                });
            }
            return Ok(AgentOutcome::Done {
                text: assistant_text,
                steps: step,
                tool_calls: tool_calls_made,
            });
        }

        // This turn wants tools. EVERY ToolUse we just appended MUST get a
        // matching ToolResult, or the transcript is an invalid incomplete-
        // tool-call state that breaks a later continuation.
        // So we process every call: once a cap/budget stop fires we keep
        // looping but synthesize a "not executed" result for each remaining
        // call, then return Stopped after the turn's calls are all answered.
        let mut stop: Option<StopReason> = over_budget.then_some(StopReason::BudgetExceeded);
        for call in &turn.tool_calls {
            if stop.is_none() && tool_calls_made >= config.max_tool_calls {
                stop = Some(StopReason::ToolCallCapReached);
            }
            if let Some(reason) = &stop {
                // Answer the ToolUse so the transcript stays valid; do NOT run
                // the tool — we are over a cap/budget.
                let label = not_executed_label(reason);
                push_tool_result(transcript, call, label);
                events.emit(AgentEvent::ToolResult {
                    name: call.name.clone(),
                    content: label.to_owned(),
                    is_error: true,
                });
                continue;
            }
            tool_calls_made += 1;

            let preview = dispatch.approval_preview(&call.name, &call.arguments);
            events.emit(AgentEvent::ToolCall {
                name: call.name.clone(),
                arguments: preview.clone(),
            });

            // Side-effects gate. An unknown tool is treated as side-effecting
            // (fail-safe) — but in practice it isn't in `tool_defs`, so the
            // dispatch impl would also reject it.
            let side_effecting = side_effects.get(&call.name).copied().unwrap_or(true);
            if side_effecting {
                events.emit(AgentEvent::ApprovalRequested {
                    id: call.id.clone(),
                    name: call.name.clone(),
                    arguments: preview,
                });
                if let ApprovalDecision::Rejected(reason) = approval.authorize(call).await {
                    events.emit(AgentEvent::ApprovalRejected {
                        name: call.name.clone(),
                        reason: reason.clone(),
                    });
                    // Feed the rejection back as the tool result so the model
                    // adapts instead of silently retrying.
                    push_tool_result(transcript, call, &format!("REJECTED by operator: {reason}"));
                    events.emit(AgentEvent::ToolResult {
                        name: call.name.clone(),
                        content: format!("REJECTED by operator: {reason}"),
                        is_error: true,
                    });
                    continue;
                }
            }

            // Execute. A dispatch error is surfaced to the model as an error
            // tool-result rather than aborting the whole run (the model can
            // recover or report it); a transport-level failure is propagated.
            let outcome = dispatch.call_tool(&call.name, &call.arguments).await?;
            push_tool_result(transcript, call, &outcome.content);
            events.emit(AgentEvent::ToolResult {
                name: call.name.clone(),
                content: outcome.content,
                is_error: outcome.is_error,
            });
        }

        // A cap/budget stop fired mid-turn: we synthesized results above so the
        // transcript stays valid; now end the run.
        if let Some(reason) = stop {
            return Ok(AgentOutcome::Stopped {
                reason,
                steps: step,
                tool_calls: tool_calls_made,
            });
        }
    }

    Ok(AgentOutcome::Stopped {
        reason: StopReason::StepCapReached,
        steps: max_steps,
        tool_calls: tool_calls_made,
    })
}

/// The synthetic tool-result text recorded for a ToolUse the loop refused to
/// execute because a cap/budget stop fired — keeps the transcript free of a
/// dangling ToolUse while honestly recording that the tool did not run.
fn not_executed_label(reason: &StopReason) -> &'static str {
    match reason {
        StopReason::ToolCallCapReached => "NOT EXECUTED: tool-call cap reached for this run",
        StopReason::BudgetExceeded => "NOT EXECUTED: token budget exceeded for this run",
        StopReason::StepCapReached => "NOT EXECUTED: step cap reached for this run",
    }
}

/// Append a `Tool`-role message carrying the result for `call`. The
/// `tool_call_id` mirrors the call's `id` so the model correlates it.
fn push_tool_result(transcript: &mut Vec<CanonicalMessage>, call: &AgentToolCall, content: &str) {
    transcript.push(CanonicalMessage {
        role: Role::Tool,
        content: vec![ContentPart::ToolResult {
            tool_call_id: call.id.clone(),
            content: content.to_owned(),
        }],
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentTool, ApprovalDecision, ToolOutcome, VecEventSink};
    use async_trait::async_trait;
    use std::sync::Mutex;
    use waygate_llm_translate::CanonicalTool;

    // --- fakes ---------------------------------------------------------------

    /// A model that replays a scripted sequence of turns, one per `complete`.
    struct ScriptedModel {
        turns: Mutex<std::collections::VecDeque<crate::ModelTurn>>,
        calls: Mutex<u32>,
    }
    impl ScriptedModel {
        fn new(turns: Vec<crate::ModelTurn>) -> Self {
            Self {
                turns: Mutex::new(turns.into()),
                calls: Mutex::new(0),
            }
        }
    }
    #[async_trait]
    impl AgentModel for ScriptedModel {
        async fn complete(
            &self,
            _messages: &[CanonicalMessage],
            _tools: &[CanonicalTool],
        ) -> Result<crate::ModelTurn, AgentError> {
            *self.calls.lock().unwrap() += 1;
            self.turns
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| AgentError::Model("script exhausted".into()))
        }
    }

    /// A dispatch that offers a fixed tool set and records the calls it gets.
    struct FakeDispatch {
        preview: Option<String>,
        tools: Vec<AgentTool>,
        calls: Mutex<Vec<(String, String)>>,
    }
    impl FakeDispatch {
        fn new(tools: Vec<AgentTool>) -> Self {
            Self {
                preview: None,
                tools,
                calls: Mutex::new(Vec::new()),
            }
        }
    }
    #[async_trait]
    impl AgentToolDispatch for FakeDispatch {
        fn approval_preview(&self, _name: &str, arguments: &str) -> String {
            self.preview.clone().unwrap_or_else(|| arguments.to_owned())
        }
        async fn available_tools(&self) -> Result<Vec<AgentTool>, AgentError> {
            Ok(self.tools.clone())
        }
        async fn call_tool(&self, name: &str, arguments: &str) -> Result<ToolOutcome, AgentError> {
            self.calls
                .lock()
                .unwrap()
                .push((name.to_owned(), arguments.to_owned()));
            Ok(ToolOutcome {
                content: format!("ok({name})"),
                is_error: false,
            })
        }
    }

    struct RejectAll;
    #[async_trait]
    impl ApprovalGate for RejectAll {
        async fn authorize(&self, _call: &AgentToolCall) -> ApprovalDecision {
            ApprovalDecision::Rejected("not now".into())
        }
    }

    // --- builders ------------------------------------------------------------

    fn tool(name: &str, side_effects: bool) -> AgentTool {
        AgentTool {
            definition: CanonicalTool {
                name: name.to_owned(),
                description: None,
                parameters: serde_json::json!({"type": "object"}),
                strict: None,
            },
            side_effects,
        }
    }

    fn tool_call(id: &str, name: &str) -> AgentToolCall {
        AgentToolCall {
            id: id.to_owned(),
            name: name.to_owned(),
            arguments: "{}".to_owned(),
        }
    }

    fn turn_with_tool(id: &str, name: &str) -> crate::ModelTurn {
        crate::ModelTurn {
            assistant: CanonicalMessage {
                role: Role::Assistant,
                content: vec![ContentPart::ToolUse {
                    id: id.to_owned(),
                    name: name.to_owned(),
                    arguments: "{}".to_owned(),
                }],
            },
            tool_calls: vec![tool_call(id, name)],
            usage_tokens: 10,
        }
    }

    fn final_turn(text: &str) -> crate::ModelTurn {
        crate::ModelTurn {
            assistant: CanonicalMessage {
                role: Role::Assistant,
                content: vec![ContentPart::Text {
                    text: text.to_owned(),
                }],
            },
            tool_calls: vec![],
            usage_tokens: 5,
        }
    }

    /// A turn that asks for TWO tool calls (two `ToolUse` parts on the assistant
    /// message), for exercising the per-turn cap / dangling-tool-use invariant.
    fn turn_with_two_tools(id1: &str, id2: &str, name: &str) -> crate::ModelTurn {
        crate::ModelTurn {
            assistant: CanonicalMessage {
                role: Role::Assistant,
                content: vec![
                    ContentPart::ToolUse {
                        id: id1.to_owned(),
                        name: name.to_owned(),
                        arguments: "{}".to_owned(),
                    },
                    ContentPart::ToolUse {
                        id: id2.to_owned(),
                        name: name.to_owned(),
                        arguments: "{}".to_owned(),
                    },
                ],
            },
            tool_calls: vec![tool_call(id1, name), tool_call(id2, name)],
            usage_tokens: 10,
        }
    }

    /// The transcript invariant: every `ToolUse` id must have a
    /// matching `ToolResult.tool_call_id`, so no model turn is left with an
    /// unanswered tool call that would poison a later continuation.
    fn assert_tooluse_balanced(transcript: &[CanonicalMessage]) {
        use std::collections::BTreeSet;
        let mut uses = BTreeSet::new();
        let mut results = BTreeSet::new();
        for m in transcript {
            for p in &m.content {
                match p {
                    ContentPart::ToolUse { id, .. } => {
                        uses.insert(id.clone());
                    }
                    ContentPart::ToolResult { tool_call_id, .. } => {
                        results.insert(tool_call_id.clone());
                    }
                    _ => {}
                }
            }
        }
        assert_eq!(
            uses, results,
            "every ToolUse must have a matching ToolResult (no dangling tool call in the transcript)",
        );
    }

    fn cfg(max_steps: u32, max_tool_calls: u32, token_budget: Option<u64>) -> AgentRunConfig {
        AgentRunConfig {
            max_steps,
            max_tool_calls,
            token_budget,
        }
    }

    fn seed() -> Vec<CanonicalMessage> {
        vec![CanonicalMessage {
            role: Role::User,
            content: vec![ContentPart::Text {
                text: "do the thing".into(),
            }],
        }]
    }

    // --- tests ---------------------------------------------------------------

    #[tokio::test]
    async fn read_tool_then_final_answer() {
        // Turn 1 calls a read (non-side-effecting) tool; turn 2 answers.
        let model = ScriptedModel::new(vec![
            turn_with_tool("c1", "read_tool"),
            final_turn("here is the answer"),
        ]);
        let dispatch = FakeDispatch::new(vec![tool("read_tool", false)]);
        let mut events = VecEventSink::default();
        let mut transcript = seed();

        let outcome = run_agent(
            &model,
            &dispatch,
            &crate::AllowAllApproval,
            &cfg(8, 16, None),
            &mut transcript,
            &mut events,
        )
        .await
        .unwrap();

        assert_eq!(
            outcome,
            AgentOutcome::Done {
                text: "here is the answer".into(),
                steps: 2,
                tool_calls: 1,
            }
        );
        // The read tool ran without an approval event (non-side-effecting).
        assert_eq!(dispatch.calls.lock().unwrap().len(), 1);
        assert!(!events
            .events
            .iter()
            .any(|e| matches!(e, AgentEvent::ApprovalRequested { .. })));
        // Transcript grew: user, assistant(tooluse), tool(result), assistant(final).
        assert_eq!(transcript.len(), 4);
        assert!(matches!(transcript[2].role, Role::Tool));
    }

    #[tokio::test]
    async fn approval_and_call_events_use_safe_preview_while_dispatch_keeps_arguments() {
        let mut turn = turn_with_tool("c1", "write_tool");
        turn.tool_calls[0].arguments = r#"{"contents":"synthetic-private-input"}"#.to_owned();
        let ContentPart::ToolUse { arguments, .. } = &mut turn.assistant.content[0] else {
            panic!("tool-use turn");
        };
        *arguments = turn.tool_calls[0].arguments.clone();
        let model = ScriptedModel::new(vec![turn, final_turn("done")]);
        let mut dispatch = FakeDispatch::new(vec![tool("write_tool", true)]);
        dispatch.preview = Some("Reviewed consequence; contents redacted.".to_owned());
        let mut events = VecEventSink::default();
        run_agent(
            &model,
            &dispatch,
            &crate::AllowAllApproval,
            &cfg(8, 16, None),
            &mut seed(),
            &mut events,
        )
        .await
        .unwrap();
        let previews: Vec<_> = events
            .events
            .iter()
            .filter_map(|event| match event {
                AgentEvent::ToolCall { arguments, .. }
                | AgentEvent::ApprovalRequested { arguments, .. } => Some(arguments),
                _ => None,
            })
            .collect();
        assert_eq!(previews.len(), 2);
        assert!(previews
            .iter()
            .all(|preview| preview.as_str() == "Reviewed consequence; contents redacted."));
        assert!(dispatch.calls.lock().unwrap()[0]
            .1
            .contains("synthetic-private-input"));
    }

    #[tokio::test]
    async fn side_effecting_tool_requires_approval_and_runs_when_approved() {
        let model =
            ScriptedModel::new(vec![turn_with_tool("c1", "write_tool"), final_turn("done")]);
        let dispatch = FakeDispatch::new(vec![tool("write_tool", true)]);
        let mut events = VecEventSink::default();
        let mut transcript = seed();

        run_agent(
            &model,
            &dispatch,
            &crate::AllowAllApproval,
            &cfg(8, 16, None),
            &mut transcript,
            &mut events,
        )
        .await
        .unwrap();

        // The side-effecting tool emitted an approval request AND ran.
        assert!(events
            .events
            .iter()
            .any(|e| matches!(e, AgentEvent::ApprovalRequested { .. })));
        assert_eq!(dispatch.calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn rejected_side_effecting_tool_does_not_run_and_feeds_rejection_back() {
        // Model insists on the write tool; the gate rejects; the loop must NOT
        // execute it, must feed a rejection result back, and (script) then ends.
        let model = ScriptedModel::new(vec![
            turn_with_tool("c1", "write_tool"),
            final_turn("ok, skipped"),
        ]);
        let dispatch = FakeDispatch::new(vec![tool("write_tool", true)]);
        let mut events = VecEventSink::default();
        let mut transcript = seed();

        let outcome = run_agent(
            &model,
            &dispatch,
            &RejectAll,
            &cfg(8, 16, None),
            &mut transcript,
            &mut events,
        )
        .await
        .unwrap();

        // The tool was NEVER executed (the whole point of the gate).
        assert!(
            dispatch.calls.lock().unwrap().is_empty(),
            "a rejected side-effecting tool must not run",
        );
        assert!(events
            .events
            .iter()
            .any(|e| matches!(e, AgentEvent::ApprovalRejected { .. })));
        // A rejection tool-result was fed back to the model.
        let fed_rejection = transcript.iter().any(|m| {
            matches!(m.role, Role::Tool)
                && m.content.iter().any(|p| {
                    matches!(
                        p,
                        ContentPart::ToolResult { content, .. } if content.contains("REJECTED")
                    )
                })
        });
        assert!(fed_rejection, "rejection must be fed back as a tool result");
        assert!(matches!(outcome, AgentOutcome::Done { .. }));
    }

    #[tokio::test]
    async fn step_cap_stops_a_tool_looping_model() {
        // A model that always wants another tool call hits the step cap.
        let model = ScriptedModel::new(vec![
            turn_with_tool("c1", "read_tool"),
            turn_with_tool("c2", "read_tool"),
            turn_with_tool("c3", "read_tool"),
        ]);
        let dispatch = FakeDispatch::new(vec![tool("read_tool", false)]);
        let mut events = VecEventSink::default();
        let mut transcript = seed();

        let outcome = run_agent(
            &model,
            &dispatch,
            &crate::AllowAllApproval,
            &cfg(3, 16, None),
            &mut transcript,
            &mut events,
        )
        .await
        .unwrap();

        assert_eq!(
            outcome,
            AgentOutcome::Stopped {
                reason: StopReason::StepCapReached,
                steps: 3,
                tool_calls: 3,
            }
        );
    }

    #[tokio::test]
    async fn tool_call_cap_stops_mid_run() {
        let model = ScriptedModel::new(vec![
            turn_with_tool("c1", "read_tool"),
            turn_with_tool("c2", "read_tool"),
        ]);
        let dispatch = FakeDispatch::new(vec![tool("read_tool", false)]);
        let mut events = VecEventSink::default();
        let mut transcript = seed();

        let outcome = run_agent(
            &model,
            &dispatch,
            &crate::AllowAllApproval,
            &cfg(8, 1, None), // only one tool call allowed
            &mut transcript,
            &mut events,
        )
        .await
        .unwrap();

        assert_eq!(
            outcome,
            AgentOutcome::Stopped {
                reason: StopReason::ToolCallCapReached,
                steps: 2,
                tool_calls: 1,
            }
        );
        assert_eq!(dispatch.calls.lock().unwrap().len(), 1);
        assert_tooluse_balanced(&transcript);
    }

    #[tokio::test]
    async fn token_budget_stops_the_run() {
        // Each tool turn uses 10 tokens; budget 5 ⇒ stop after the first turn,
        // before executing its tool.
        let model = ScriptedModel::new(vec![
            turn_with_tool("c1", "read_tool"),
            final_turn("unreached"),
        ]);
        let dispatch = FakeDispatch::new(vec![tool("read_tool", false)]);
        let mut events = VecEventSink::default();
        let mut transcript = seed();

        let outcome = run_agent(
            &model,
            &dispatch,
            &crate::AllowAllApproval,
            &cfg(8, 16, Some(5)),
            &mut transcript,
            &mut events,
        )
        .await
        .unwrap();

        assert_eq!(
            outcome,
            AgentOutcome::Stopped {
                reason: StopReason::BudgetExceeded,
                steps: 1,
                tool_calls: 0,
            }
        );
        assert!(
            dispatch.calls.lock().unwrap().is_empty(),
            "budget stop must precede the turn's side effects",
        );
        assert_tooluse_balanced(&transcript);
    }

    #[tokio::test]
    async fn tool_call_cap_synthesizes_results_for_unexecuted_calls() {
        // One turn with TWO tool calls but only ONE allowed: call 1 runs, call
        // 2 is answered with a synthetic "not executed" result so the transcript
        // has no dangling ToolUse.
        let model = ScriptedModel::new(vec![turn_with_two_tools("c1", "c2", "read_tool")]);
        let dispatch = FakeDispatch::new(vec![tool("read_tool", false)]);
        let mut events = VecEventSink::default();
        let mut transcript = seed();

        let outcome = run_agent(
            &model,
            &dispatch,
            &crate::AllowAllApproval,
            &cfg(8, 1, None),
            &mut transcript,
            &mut events,
        )
        .await
        .unwrap();

        assert_eq!(
            outcome,
            AgentOutcome::Stopped {
                reason: StopReason::ToolCallCapReached,
                steps: 1,
                tool_calls: 1,
            }
        );
        assert_eq!(
            dispatch.calls.lock().unwrap().len(),
            1,
            "only the one allowed tool actually ran",
        );
        // Both ToolUse parts are answered — the unexecuted one with a synthetic
        // result — so the transcript is valid for persistence/continuation.
        assert_tooluse_balanced(&transcript);
    }

    #[tokio::test]
    async fn token_budget_stops_even_on_final_answer() {
        // A final-answer turn whose usage tips over the budget reports
        // BudgetExceeded, not Done — the cap is a hard invariant. The answer
        // text is still streamed (not hidden).
        let model = ScriptedModel::new(vec![final_turn("answer that costs too much")]); // usage 5
        let dispatch = FakeDispatch::new(vec![tool("read_tool", false)]);
        let mut events = VecEventSink::default();
        let mut transcript = seed();

        let outcome = run_agent(
            &model,
            &dispatch,
            &crate::AllowAllApproval,
            &cfg(8, 16, Some(4)),
            &mut transcript,
            &mut events,
        )
        .await
        .unwrap();

        assert_eq!(
            outcome,
            AgentOutcome::Stopped {
                reason: StopReason::BudgetExceeded,
                steps: 1,
                tool_calls: 0,
            }
        );
        assert!(
            events.events.iter().any(|e| matches!(
                e,
                AgentEvent::AssistantText { text } if text.contains("costs too much")
            )),
            "the final answer text is still streamed even though the run is over budget",
        );
    }
}
