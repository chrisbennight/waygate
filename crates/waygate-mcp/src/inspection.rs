//! Response-inspector pipeline.
//!
//! Stage 11 (`inspect_response`) of [`DefaultInvocationService`]
//! runs every configured [`Inspector`] against the upstream's
//! [`CallToolResult`] before the response is forwarded to the
//! caller. Inspectors look for things the per-call gate can't
//! see at request time — PII, secrets, prompt-injection markers,
//! tool-poisoning attempts.
//!
//! ## Scope
//!
//! The trait + the built-in inspectors:
//! - [`pii::PiiInspector`] — US PII patterns
//! - [`secrets::SecretsInspector`] — AWS / GitHub / JWT / PEM
//! - [`poisoning::PoisoningInspector`] — prompt-injection
//!   canaries
//!
//! All three are opt-in via independent env vars in
//! `waygate-server::main`; default off ⇒ stage 11 is a no-op.
//! Native `resources/read` reuses the same chain by projecting only textual
//! resource contents into a `CallToolResult`, applying composed redactions
//! back to those text fields, and leaving blob contents opaque. That path
//! identifies the operation as `resources/read`, uses the resource's governed
//! risk, and sets `pii_classified=false` because resources have no tool-output
//! PII declaration.
//!
//! ## Chain semantics (Pass / Block / Redact)
//!
//! Stage 11 runs inspectors sequentially in registration order:
//!
//! - [`Decision::Pass`] — working result unchanged; continue
//!   to the next inspector.
//! - [`Decision::Redact`] — working result replaced
//!   by `decision.redacted`; subsequent inspectors see the
//!   redacted version (redactions compose); the orchestrator
//!   emits one summary `CallTool/Success` audit row per
//!   inspector that redacted + bumps
//!   `mcp_response_inspector_redactions_total{inspector}`.
//! - [`Decision::Block`] — first Block short-circuits the
//!   chain and returns
//!   [`waygate_invocation::InvocationError::ResponseInspectionBlocked`];
//!   the blocked inspector's name is preserved so operators
//!   reading the audit row know which rule fired.
//!
//! ## Safety
//!
//! Block reasons MUST NOT include the matched payload — only the
//! inspector name + the rule label (e.g. `"US_SSN"`). The same
//! discipline applies to schema-violation reasons; the
//! adapter at [`crate::server`] preserves the contract on the
//! wire by including only `{ inspector_name, reason }` in the
//! MCP error data envelope, never the original `structured_content`.

use std::sync::Arc;

use async_trait::async_trait;
use rmcp::model::CallToolResult;

use waygate_core::RiskTier;

pub mod pii;
pub mod poisoning;
pub mod secrets;

/// What an inspector returns after examining a response.
///
/// Besides [`Pass`](Self::Pass) + [`Block`](Self::Block) there
/// is [`Redact`](Self::Redact), so an inspector can
/// modify the upstream response in place (e.g. replace a
/// matched SSN with `[REDACTED:US_SSN]`) instead of refusing
/// the call entirely. The orchestrator threads the
/// replacement back to the caller.
#[derive(Debug)]
pub enum Decision {
    /// No finding; the response is forwarded unchanged. The
    /// fast path — inspectors that hit this for >99 % of calls
    /// (the common shape) cost only their match work.
    Pass,
    /// Refuse to forward. Sanitized reason — must NOT carry the
    /// matched payload; only the inspector name + rule label.
    /// See [`crate::server::dispatch_tool_call`] for the wire
    /// shape the rmcp adapter produces from this.
    Block { reason: String },
    /// Forward, but with this modified result instead of the
    /// upstream's original. `findings_count` reports how many
    /// individual matches were redacted so the orchestrator can
    /// emit ONE summary audit row + metric per inspector per
    /// inspection (anti-flood: never N rows for N matches).
    /// Subsequent inspectors in the chain see the redacted
    /// output — redactions compose.
    Redact {
        redacted: CallToolResult,
        findings_count: u32,
    },
}

/// Per-invocation metadata an inspector receives alongside the
/// response. Borrowed across the inspector chain so the
/// orchestrator pays no clone cost per inspector.
#[derive(Debug)]
pub struct InspectionContext<'a> {
    pub tenant: &'a str,
    pub principal_sub: Option<&'a str>,
    pub server: &'a str,
    /// Bare tool name (NOT `<server>.<tool>`).
    pub tool: &'a str,
    pub risk: RiskTier,
    /// `true` when the catalog has the tool classified as
    /// PII-producing. Informational — does NOT skip the
    /// inspector. A tool not classified as PII but emitting a
    /// SSN is exactly the case the inspector catches.
    pub pii_classified: bool,
}

/// The trait every response inspector implements.
///
/// `async` because planned external adapters (Lakera, ZenGuard)
/// will be HTTP-bound; making the contract async now
/// avoids a breaking change later. Built-in inspectors today
/// run sync-pure work inside the async fn.
#[async_trait]
pub trait Inspector: Send + Sync + 'static {
    /// Stable label used in audit rows / Prometheus metric
    /// labels / error data. `&'static str` matches the
    /// `InvocationError::kind()` precedent — these are
    /// dashboard keys, not user-facing strings.
    fn name(&self) -> &'static str;

    /// Examine the upstream response. Inspectors may
    /// return [`Decision::Pass`], [`Decision::Block`], or
    /// [`Decision::Redact`]. The chain in
    /// [`crate::invocation::DefaultInvocationService::inspect_response`]
    /// runs inspectors in registration order; each `Redact`
    /// replaces the working result, subsequent inspectors see
    /// the redacted output (redactions compose); the first
    /// `Block` short-circuits the chain into
    /// [`waygate_invocation::InvocationError::ResponseInspectionBlocked`].
    async fn inspect(&self, ctx: &InspectionContext<'_>, result: &CallToolResult) -> Decision;
}

/// Type-erased handle for composition-root wiring.
pub type SharedInspector = Arc<dyn Inspector>;

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysPass;
    #[async_trait]
    impl Inspector for AlwaysPass {
        fn name(&self) -> &'static str {
            "always_pass"
        }
        async fn inspect(&self, _: &InspectionContext<'_>, _: &CallToolResult) -> Decision {
            Decision::Pass
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pass_decision_constructs_and_round_trips_through_dyn_trait() {
        let i: SharedInspector = Arc::new(AlwaysPass);
        assert_eq!(i.name(), "always_pass");
        let ctx = InspectionContext {
            tenant: "default",
            principal_sub: Some("alice"),
            server: "example-messages",
            tool: "send",
            risk: RiskTier::Low,
            pii_classified: false,
        };
        let res = CallToolResult::success(vec![]);
        let d = i.inspect(&ctx, &res).await;
        assert!(matches!(d, Decision::Pass));
    }
}
