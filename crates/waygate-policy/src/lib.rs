//! Durable, versioned Cedar policy bundles.
//!
//! This crate's seed is the trait + types + Pg impl + migration
//! `0012_policy`. Production wiring then landed, mirroring how the
//! catalog (`waygate-catalog`) was rolled out:
//!
//! - **import**: a `--import-policies <dir>` command reads the
//!   existing `policies/*.cedar` files into a v1 `published` bundle so
//!   a deploy can cut over without losing the current policy set.
//! - **loader wiring**: the default tenant uses the file-as-truth model. The
//!   on-disk `policies/*.cedar` set is its SOURCE OF TRUTH at boot/SIGHUP, and
//!   this store is the durable HISTORY / RECOVERY ledger beside it. A default
//!   publish mirrors to disk before recording the ledger row. Non-default
//!   tenants have no competing filesystem namespace: their latest published
//!   bundles are compiled from this store into the runtime tenant registry at
//!   boot and on the policy doorbell/poll path.
//! - **lifecycle + simulation**: `rollback_to` is wired; `run_tests`
//!   (evaluating a candidate bundle against stored simulation cases,
//!   which needs the Cedar evaluator) remains out of this
//!   dependency-light seed and lives on the admin side.
//!
//! The crate is kept dependency-light (no cedar-policy, no axum) so it
//! mirrors `waygate-catalog`: callers depend on the policy *types* and
//! *store* without pulling in the evaluator or transport machinery.

mod import;
mod store;
mod types;

pub use import::{
    canonical_policy_disk_hash, canonical_policy_source, clear_policy_dir,
    policy_sources_equivalent, read_policy_dir, write_policy_bundle_to_dir,
    write_policy_bundle_to_dir_from_base, PolicyDirContents, PolicyDirWriteError, PUBLISHED_FILE,
};
pub use store::{
    PgPolicyStore, PolicyStore, SharedPolicyStore, FILESYSTEM_ACTOR, POLICY_RELOAD_CHANNEL,
    RECONCILE_GRACE,
};
pub use types::{
    content_hash, ActivePolicyBundleSignature, PointerReconcile, PolicyBundle, PolicyBundlePage,
    PolicyBundleSummary, PolicyError, PolicyHistoryFilter, PolicyPointer, PolicyStatus,
    TurnstileOutcome,
};
