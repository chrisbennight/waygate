//! Single integration-test binary for waygate-admin's API-surface suites.
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
//! owns one API surface, and a regression test folds into the module
//! that owns the violated contract. Modules must stay parallel-safe
//! without process isolation: under `cargo test` they now share one
//! process (thread-per-test), while cargo-nextest still runs each test
//! in its own process — so no `std::env::set_var`, no shared fixture
//! rows without a per-test suffix, and cross-test serialization needs a
//! nextest test-group in `.config/nextest.toml`, not just a process-
//! local lock (see `discovery-pg` there for the pattern).
//!
//! The dashboard render suites stay in the sibling `dashboard_render`
//! target, which already uses this same one-binary module layout.

mod approval_grants_api;
mod catalog_api;
mod change_requests_api;
mod codemode_executions_api;
mod confidential_clients_api;
mod dashboard_server_manifests;
mod hitl_ws_integration;
mod manifest_bundles_api;
mod openapi_dump;
mod openapi_spec;
mod pg_admin_mutation_audit;
mod pg_tenant_lifecycle;
mod policy_bundles_api;
mod scope_gating;
mod serve_dir;
mod style_tokens;
mod upstream_sessions_api;

mod skill_reviews_pg;
