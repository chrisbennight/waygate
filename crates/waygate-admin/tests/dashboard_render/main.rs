//! Dashboard render-contract suite (formerly the monolithic
//! `dashboard_render.rs`, 13,953 lines). One test target, one module
//! per page family, mirroring the `dashboard_*.rs` source split.
//! Shared builders/fakes live in [`common`] and the `AdminState` core
//! in [`admin_state`]; the canonical pg preamble and mocks live in
//! `waygate-test-support`.

mod common;
// Shared with the `suite` target. It lives with the admin tests so
// `waygate-test-support` does not depend on `waygate-admin`.
#[path = "../support/admin_state.rs"]
mod admin_state;

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
