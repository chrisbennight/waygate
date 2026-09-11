//! The LLM budget gate (lagging enforcement, invariant I3).
//!
//! Consulted by the LLM path's check_quota stage BEFORE the irreversible
//! provider call. It reports whether the principal is ALREADY at/over an
//! applicable token/cost budget — reading RECORDED usage (the `llm_usage`
//! ledger), never estimating the in-flight call. Implemented by the storage
//! layer (`waygate_storage::PgLlmBudgetGate`); `None` on the pipeline ⇒ no
//! budget enforcement (DB-less / inference-disabled deployments).
//!
//! Bound scope: the ledger advances when a call's usage is recorded (unary
//! collection, or a stream's `[DONE]`). For OpenAI-chat streaming the provider
//! reports usage only at the terminal frame, so a stream abandoned before
//! `[DONE]` is NOT token-ledgered — the token/cost budget bounds completed-call
//! overrun (~1 request), while the stage-6 request-rate quota bounds how often
//! such (possibly-abandoned) calls can be started. See 0049_llm_budgets.sql.

use async_trait::async_trait;

/// A tripped budget: which dimension was exhausted (`"tokens"` / `"cost"`) and
/// an operator-readable detail. Carries no principal/prompt content.
#[derive(Debug, Clone)]
pub struct BudgetRejection {
    pub dimension: String,
    pub reason: String,
}

/// Lagging budget gate. Returns `Some(rejection)` when the principal has
/// already met or exceeded an applicable budget (the call must be refused),
/// `None` when within budget or no budget applies.
///
/// Failure posture is the implementation's concern: the Postgres gate fails
/// OPEN on a budget-store error (logs + returns `None`) — a budget is
/// cost-control with bounded-overrun semantics, not a security boundary, so a
/// transient DB blip should not take all inference offline.
#[async_trait]
pub trait LlmBudgetGate: Send + Sync + 'static {
    async fn check(
        &self,
        tenant_id: &str,
        principal_sub: Option<&str>,
        model_alias: &str,
    ) -> Option<BudgetRejection>;
}

/// Shared, cheaply-cloneable handle to the budget gate.
pub type SharedLlmBudgetGate = std::sync::Arc<dyn LlmBudgetGate>;
