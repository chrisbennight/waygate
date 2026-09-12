//! Governed catalog of upstream MCP servers, tools, versions,
//! classifications, approvals, and drift events.
//!
//! This crate provides the `CatalogStore` trait, its domain types, and a
//! Postgres implementation. Three pieces wire it into the running gateway:
//!
//! - [`ManifestImporter`] reads complete manifest generations into the catalog
//!   tables for both explicit `gateway-server --import-manifests` runs and
//!   automatic reconciliation after an accepted live-file reload.
//! - `UpstreamPool::resolve_invocation_tool()` consults `CatalogStore::resolve_tool()`
//!   first and falls back to the manifest-backed `UpstreamPool::tool_facts()`
//!   on a miss, an error, or when no catalog store is wired (no Postgres
//!   pool configured). SIGHUP-driven YAML manifest reload stays in place as
//!   that fallback path; removing it is a separate, later change.
//! - `waygate-admin` exposes catalog read views, immediate quarantine, initial
//!   approval, and a change-request-gated, versioned durable unquarantine
//!   transition.
//!
//! The crate is kept dependency-light (no rmcp, no axum, no tower) so other
//! crates can depend on the catalog types without pulling in transport
//! machinery.

pub mod grant_sweeper;
mod import;
mod schema_hash;
mod store;
pub mod tool_reviews;
mod types;

pub use import::{ImportOperation, ImportServer, ImportStats, ImportTool, ManifestImporter};
pub use schema_hash::{
    approval_binding_hash, argument_hash, behavior_hash, manifest_classification_hash, schema_hash,
    validator_schema_hash, ClassifiedOperation,
};
pub use store::{CatalogStore, PgCatalogStore, SharedCatalogStore};
pub use types::{
    ApprovalAction, ApprovalGrant, ApprovalGrantExecutionBinding, CatalogError,
    CatalogServerStatus, CatalogServerStatusChange, CatalogServerSummary,
    CatalogServerTransitionTarget, CatalogVisibility, DriftEvent, DriftObservation, DriftSeverity,
    GrantExecutionBinding, GrantFilter, GrantLifecycle, GrantLookup, NewApprovalGrant,
    OperationClassification, ResolvedTool, SubjectType, ToolDefinition,
};

/// PostgreSQL doorbell emitted transactionally after a governed-catalog change
/// that can alter an authorized discovery view.
pub const CATALOG_RELOAD_CHANNEL: &str = "mcp_catalog_reload";
