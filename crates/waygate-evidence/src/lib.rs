//! Shared audit/evidence and inference-plane seam types.
//!
//! This crate owns the shared types consumed by the protocol layer and by
//! implementations such as `waygate-storage` and `waygate-as`, keeping those
//! implementations independent of the MCP protocol crate.
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
