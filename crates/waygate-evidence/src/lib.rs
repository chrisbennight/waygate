//! Shared audit/evidence and inference-plane seam types.
//!
//! These four modules were extracted from
//! `waygate-mcp` so that the crates *below* the MCP layer that implement
//! the traits — `waygate-storage` (audit sink, LLM cache/usage/budget
//! stores) and `waygate-as` (OAuth-event audit) — no longer depend *up*
//! on the protocol crate for pure types. `waygate-mcp` re-exports every
//! path it used to own (`waygate_mcp::audit`, `::cache`, `::usage`,
//! `::budget`, and the crate-root aliases), so its consumers are
//! unaffected; the canonical home is here.
//!
//! The pattern each module follows is identical: this crate defines the
//! trait and its DTOs, a storage crate provides the Postgres
//! implementation, and the composition root (`waygate-server`) injects a
//! `dyn` handle into the invocation pipeline.
//!
//! Layering: depends on `waygate-core` (`RiskTier`, `TenantId`),
//! `waygate-oidc` (`Principal` → [`audit::AuditPrincipal`]), and
//! `waygate-telemetry` (trace-id stamping) — nothing above.

pub mod audit;
pub mod budget;
pub mod cache;
pub mod usage;

pub use audit::{
    AuditEvent, AuditMode, AuditOutcome, AuditPrincipal, EvidenceCategory, EvidenceError,
    EvidenceRecorder, NullSink, SharedEvidence,
};
pub use budget::{BudgetRejection, LlmBudgetGate, SharedLlmBudgetGate};
pub use cache::{CacheStoreRequest, CachedCompletion, LlmCache, SharedLlmCache};
pub use usage::{LlmUsageRecorder, LlmUsageRow, SharedLlmUsage};
