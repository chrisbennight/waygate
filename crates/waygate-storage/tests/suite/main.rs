//! Single integration-test binary for waygate-storage's suites.
//!
//! Each module below was previously its own `tests/*.rs` binary; one
//! binary per module meant one link job per module, and linking the
//! many-binary layout dominated CI's compile phase. Cargo compiles this
//! whole directory as ONE test target, so keep new surfaces as new
//! modules here rather than new top-level `tests/*.rs` files (a stray
//! top-level file still compiles and runs, but as its own binary,
//! re-paying the link cost this layout removes).
//!
//! Module conventions are unchanged from the per-file era: one module
//! owns one store surface, and a regression test folds into the module
//! that owns the violated contract. Modules must stay parallel-safe
//! without process isolation: under `cargo test` they now share one
//! process (thread-per-test), while cargo-nextest still runs each test
//! in its own process — so no `std::env::set_var`, no shared fixture
//! rows without a per-test suffix, and cross-test serialization needs a
//! nextest test-group in `.config/nextest.toml`, not just a process-
//! local lock (see `discovery-pg` there for the pattern).

mod agent_conversations_pg;
mod pg_llm_budgets;
mod pg_llm_cache;
mod pg_llm_catalog;
mod pg_llm_usage;
mod pg_smoke;
mod pg_touch_updated_at;
mod webhook_export_over_http;
