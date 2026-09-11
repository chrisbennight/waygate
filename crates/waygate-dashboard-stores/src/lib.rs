//! Small per-tenant dashboard-backing stores, one module each.
//!
//! Each module is a self-contained store: row/domain types, an
//! `#[async_trait]` store trait, the Pg impl over its own table, and its
//! error enum. They share nothing but the pattern — merging them into one
//! crate trades six workspace members (six manifests, six crate-map rows,
//! six dep edges from `waygate-admin`/`waygate-server`) for one, without
//! coupling the modules to each other.
//!
//! A store outgrowing "dashboard page persistence" (its own domain logic,
//! consumers beyond admin/server) should graduate back to its own crate.

pub mod activity_saved_views;
pub mod agent_config;
pub mod inspection_rules;
pub mod playground_scenarios;
pub mod scim_provisioning_log;
pub mod tasks;
