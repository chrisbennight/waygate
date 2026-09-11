//! Single integration-test binary for waygate-as's suites.
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
//! owns one OAuth/EMA surface, and a regression test folds into the
//! module that owns the violated contract. Modules must stay
//! parallel-safe without process isolation: under `cargo test` they now
//! share one process (thread-per-test), while cargo-nextest still runs
//! each test in its own process — so no `std::env::set_var`, no shared
//! fixture rows without a per-test suffix (these pg suites already
//! isolate by suffix and clean up by prefix), and cross-test
//! serialization needs a nextest test-group in `.config/nextest.toml`,
//! not just a process-local lock (see `discovery-pg` there for the
//! pattern).

mod cors_preflight;
mod ema_token_exchange;
mod idjag_redeem_pg;
mod oauth_flow_pg;
mod pg_consent_smoke;
mod pg_session_smoke;
mod token_mint_roundtrip;
