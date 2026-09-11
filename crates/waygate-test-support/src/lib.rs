//! Shared test infrastructure for the workspace's integration tests.
//!
//! **Dev-dependency only.** No production crate may list this crate in
//! `[dependencies]` — it exists so the workspace's integration tests stop
//! hand-rolling the same three shapes (F7 in the architecture review):
//!
//! - [`pg::pool_or_skip`] — the "env var → skip → connect → migrate"
//!   Postgres preamble that ~40 `*_pg` test files each reimplemented.
//! - [`admin`] — the common [`waygate_admin::AdminState`] core that
//!   the `dashboard_render/` suite's ~29 `state_with_*` builders rebuilt,
//!   plus the `example-messages` fixture manifest.
//! - [`mocks`] — the canonical in-memory fakes, one per trait, one naming
//!   convention. A recording fake that captures interactions is preferred
//!   over a static stub (see AGENTS.md "Testing conventions").
//!
//! Layering: this crate sits beside the composition crates and may depend
//! on anything; nothing depends on it except `[dev-dependencies]`, which
//! the dependency-direction tripwire deliberately exempts.

pub mod admin;
pub mod mocks;
pub mod pg;

pub mod skills;
