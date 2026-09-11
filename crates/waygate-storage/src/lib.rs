//! Audit/observability persistence: the audit sink + tamper-evidence hash
//! chain + verification, ECS/OCSF/syslog export via the evidence outbox,
//! retention policies/rollups/sweeps, the LLM cache/usage/budgets/catalog
//! stores, and agent conversation storage.

pub mod agent_conversations;
pub mod audit;
pub mod bundle;
pub mod chain_verify;
pub mod drain;
pub mod ecs;
pub mod exporter;
pub mod hashchain;
pub mod llm_budgets;
pub mod llm_cache;
pub mod llm_catalog;
pub mod llm_usage;
pub mod ocsf;
pub mod outbox;
pub mod pool;
pub mod retention;
pub mod rollup;
pub mod routing;
pub mod sweep;
pub mod syslog;

// Test-only: asserts the embedded `migrations/` dir has one file per sqlx
// version. Guards against the 2026-06-13 duplicate-0042 boot crash.
#[cfg(test)]
mod migration_versions;

pub use agent_conversations::{
    Conversation, ConversationError, ConversationMessage, ConversationStore,
    InMemoryConversationStore, NewConversation, PgConversationStore, SharedConversationStore,
};
pub use audit::{
    AuditFacets, AuditQuery, AuditReader, AuditRow, HistogramBucket, PgAuditSink, StorageError,
    ToolStat,
};
pub use bundle::{
    build_bundle, derive_signing_key_id, verify_bundle, write_bundle, BundleError, BundleFooter,
    BundleHeader, BundleRequest, BundleSigner, BundleSignerError, VerifyError,
    BUNDLE_FORMAT_VERSION,
};
pub use chain_verify::{
    recompute_row_hash, verify_chain_rows, ChainHead, ChainMismatch, ChainVerifyReport,
    ChainVerifyRow, ChainVerifyStatus, DeletedRow, MismatchKind, RetentionMarker,
};
pub use drain::{drain_one_batch, next_attempt_after, run_outbox_drain};
pub use exporter::{
    EcsExporter, ExportError, Exporter, ExporterRegistry, OcsfExporter, SyslogExporter,
    WebhookExporter,
};
pub use hashchain::{canonical_audit_bytes, compute_row_hash};
pub use llm_budgets::{
    check_llm_budget, upsert_llm_budget, BudgetDimension, BudgetExceedance, LlmBudgetRow,
    PgLlmBudgetGate,
};
pub use llm_cache::{
    cache_key, enforce_tenant_cap, get_cached, put_cached, run_llm_cache_sweep_scheduler,
    sweep_expired_llm_cache, CacheEntry, CachedResponse, PgLlmCache,
};
pub use llm_catalog::{
    get_llm_model, get_llm_model_by_served, list_discovered_llm_models, list_llm_models,
    mark_discovered_absent, upsert_discovered_llm_model, upsert_llm_model,
    LlmDiscoveredModelUpsert, LlmModelCatalog, LlmModelRow, LlmModelUpsert, PgLlmModelCatalog,
    SharedLlmModelCatalog,
};
pub use llm_usage::{compute_cost, insert_llm_usage, CostBreakdown, CostSource, PgLlmUsageSink};
pub use outbox::{dequeue_ready, enqueue, mark_delivered, mark_failed, OutboxEntry, OutboxStatus};
pub use pool::{build_pool, PoolRole};
pub use retention::{
    resolve_policy, retention_cutoff, PgRetentionStore, RetentionPolicy, RetentionStore,
};
pub use rollup::{
    rollup_facets, rollup_histogram, rollup_once, rollup_tool_stats, run_rollup_maintenance,
};
pub use routing::{
    delete_routing_row, fetch_tenant_routing, list_routing_rows, resolve_outbox_targets,
    upsert_routing_row, PgRoutingStore, RoutingRow, RoutingStore,
};
pub use sweep::{
    run_retention_scheduler, run_retention_sweep, sweep_all_policies,
    sweep_all_policies_if_tick_claimed, PgSweeper, RetentionSchedulerTick, SweepError, SweepReport,
    Sweeper, FORBIDDEN_SWEEP_CATEGORY, RETENTION_SWEEP_BATCH_ROWS,
};
