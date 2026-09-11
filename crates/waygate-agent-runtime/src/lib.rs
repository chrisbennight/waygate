//! The concrete agent runtime behind the dashboard's chat agent.
//!
//! `waygate-agent` (Domain) deliberately declares only trait seams —
//! model, dispatch, approval gate — and stays dependency-thin so every
//! consumer of the seams doesn't inherit the heavy impls. The real
//! implementations grew inside `waygate-admin` next to their dashboard
//! pages; this crate is their honest home: a sibling **Domain** crate that
//! may depend on the invocation pipeline, the LLM translation layer, and
//! the upstream pool, keeping the seam crate thin and the domain logic out
//! of a Composition crate.
//!
//! Modules moved verbatim from `waygate-admin`:
//! - [`agent_runtime`] — `OpenAiAgentModel` (the LLM-backed model impl),
//!   `UpstreamAgentDispatch` (allowlisted tool dispatch through the
//!   governed invocation pipeline), `ChatApprovalGate` (side-effect
//!   approval), and `effective_principal`.
//! - [`chat_approvals`] — the in-chat side-effects approval rendezvous the
//!   gate parks calls in and the dashboard's approve endpoint resolves.
//!
//! `waygate-admin` consumes both for the agent-chat and policy-review
//! dashboard surfaces; nothing here renders HTML or knows about askama.

pub mod agent_runtime;
pub mod chat_approvals;
