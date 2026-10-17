//! Shared test infrastructure for the workspace's integration tests.
//!
//! **Dev-dependency only.** No production crate may list this crate in
//! `[dependencies]` — it exists so the workspace's integration tests stop
//! hand-rolling the same shapes:
//!
//! - [`pg::pool_or_skip`] — the "env var → skip → connect → migrate"
//!   Postgres preamble that ~40 `*_pg` test files each reimplemented.
//! - [`mocks`] — the canonical in-memory fakes, one per trait, one naming
//!   convention. A recording fake that captures interactions is preferred
//!   over a static stub (see AGENTS.md "Testing conventions").
//!
//! Layering: this crate sits beside the composition crates and may depend
//! on anything; nothing depends on it except `[dev-dependencies]`, which
//! the dependency-direction tripwire deliberately exempts. Every test target
//! that uses it waits for everything it depends on to compile, so a fixture
//! needed by one large crate's tests, such as the `waygate-admin` state
//! core, lives with those tests instead.

pub mod mocks;
pub mod pg;
pub mod response_settings;

pub mod skills;
pub mod task_routes;
