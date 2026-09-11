//! Durable, versioned upstream-manifest bundles.
//!
//! The durable history / rollback ledger for the upstream-server set.
//! Under the file-as-truth model, the on-disk `servers/*.yaml` dir is
//! the boot/SIGHUP source of truth; this crate
//! versions the whole manifest set (draft → published → rolled_back) in
//! Postgres as the audit ledger, the rollback source, and a last-resort
//! recovery source consulted only when the on-disk set is unreadable. The
//! admin write paths mirror each published / rolled-back set onto disk and
//! record a snapshot here. It mirrors `waygate-policy` (durable Cedar
//! bundles).
//!
//! Lands the trait + types + Pg impl + migration `0037_server_manifests`,
//! the `--import-server-bundle` seed command, the admin REST
//! (`/api/v1/server_manifests/*`), and the dashboard editor. (Originally
//! the DB-as-boot-source overlay; the file-as-truth inversion demoted it
//! to the ledger role above.)
//!
//! The crate is kept dependency-light (it depends only on the manifest
//! *types* via... actually it stores `content` as opaque YAML text, so
//! it needs no manifest-crate dependency — the serialize/parse
//! helpers live in `waygate-manifest-types` next to `UpstreamManifest`
//! (re-exported by `waygate-upstream`), and
//! callers hand this store the already-serialized string).

mod store;
mod types;

pub use store::{
    ManifestStore, PgManifestStore, SharedManifestStore, FILESYSTEM_ACTOR, MANIFEST_RELOAD_CHANNEL,
    RECONCILE_GRACE,
};
pub use types::{
    content_hash, ManifestBundle, ManifestBundlePage, ManifestBundleSummary, ManifestError,
    ManifestHistoryFilter, ManifestPointer, ManifestStatus, PointerReconcile, ReplicaHeartbeat,
    TurnstileOutcome,
};
