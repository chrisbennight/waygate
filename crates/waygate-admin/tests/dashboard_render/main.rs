//! Dashboard render-contract suite (formerly the monolithic
//! `dashboard_render.rs`, 13,953 lines). One test target, one module
//! per page family, mirroring the `dashboard_*.rs` source split.
//! Shared builders/fakes live in [`common`]; the canonical pg
//! preamble, mocks, and `AdminState` core live in
//! `waygate-test-support`.

mod common;

mod activity;
mod activity_live;
mod bundles_playground;
mod chrome;
mod consent_identities;
mod crud_pages;
mod decisions;
mod editors;
mod governance_pages;
mod overview;
mod policies;
mod policy_edit_agents;
mod scim_rbac;
mod servers;
mod tenants_catalog;
mod tools;
mod try_profiles;
