//! Manifest-bundle domain types shared by the `ManifestStore` trait, the
//! Pg impl, and its callers (the boot loader, the SIGHUP reload task, and
//! the admin CRUD REST in `waygate-admin`). Mirrors `waygate-policy`'s
//! bundle types.
//!
//! All types are `Clone` + `Send + Sync` because the store is invoked
//! from the boot path, a `tokio::spawn`-ed SIGHUP reload task, and the
//! admin CRUD's `axum` handlers. A bundle's `content` is the upstream-manifest
//! set serialized as YAML — not a secret (manifests reference
//! `auth.bearer_env` *names*, never token values).

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Lifecycle of a `server_manifests` row. Mirrors `PolicyStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ManifestStatus {
    /// Staged but not eligible to be the active bundle. Boot never
    /// builds the pool from a draft.
    Draft,
    /// Eligible to be the active bundle. The newest published version
    /// wins.
    Published,
    /// Was published, later superseded by a rollback. Retained for the
    /// audit trail; never re-activated.
    RolledBack,
}

impl ManifestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Published => "published",
            Self::RolledBack => "rolled_back",
        }
    }
}

/// A full manifest bundle including its `content` (the manifest set as a
/// YAML sequence). Returned by the reads that need the source (the
/// active-bundle load, a single-bundle fetch).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ManifestBundle {
    pub id: Uuid,
    pub tenant_id: String,
    pub version: i32,
    pub status: ManifestStatus,
    /// Full upstream-manifest set: a YAML sequence of UpstreamManifest.
    pub content: String,
    /// sha256(content), hex.
    pub content_hash: String,
    pub author: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub published_at: Option<OffsetDateTime>,
    pub published_by: Option<String>,
}

/// A bundle without its (potentially large) `content` — for the list
/// endpoint, where rendering every version's full source is wasteful.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ManifestBundleSummary {
    pub id: Uuid,
    pub tenant_id: String,
    pub version: i32,
    pub status: ManifestStatus,
    pub content_hash: String,
    pub author: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub published_at: Option<OffsetDateTime>,
    pub published_by: Option<String>,
}

/// Candidate class used by bounded bundle-history reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestHistoryFilter {
    Draft,
    PreviouslyPublished,
}

impl ManifestHistoryFilter {
    pub(crate) fn matches(self, status: ManifestStatus) -> bool {
        match self {
            Self::Draft => status == ManifestStatus::Draft,
            Self::PreviouslyPublished => status != ManifestStatus::Draft,
        }
    }
}

/// One bounded page of manifest bundle summaries plus the total matching rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestBundlePage {
    pub total: u64,
    pub bundles: Vec<ManifestBundleSummary>,
}

/// The cross-replica write turnstile pointer: the hash of
/// the CURRENT live on-disk manifest set, plus who/when last advanced it.
/// One row per tenant in `server_manifest_pointer`. Coordination state, not
/// the boot source — see the migration `0038_server_manifest_pointer.sql`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestPointer {
    pub tenant_id: String,
    pub current_hash: String,
    pub updated_at: OffsetDateTime,
    pub updated_by: Option<String>,
}

/// One gateway replica's current heartbeat: the config
/// version + content hash it last loaded and when it last checked in. One row
/// per replica in `fleet_replicas`; the dashboard fleet roll-up reads these.
/// Observability state, not coordination — see `0040_fleet_replicas.sql`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaHeartbeat {
    pub replica_id: String,
    pub tenant_id: String,
    /// `None` when the on-disk set is uncommitted / out-of-band (no matching
    /// committed ledger version).
    pub version: Option<i32>,
    pub content_hash: String,
    pub updated_at: OffsetDateTime,
}

/// Result of a turnstile compare-and-swap ([`crate::ManifestStore::cas_pointer`]).
/// `Won` ⇒ this writer atomically advanced the pointer from its base hash and
/// is the one allowed to write the file; `Lost` ⇒ the live hash no longer
/// matches the base the writer edited from (another replica advanced it
/// first), so the write must be refused with "reload and retry".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnstileOutcome {
    Won,
    Lost,
}

impl TurnstileOutcome {
    pub fn won(self) -> bool {
        matches!(self, Self::Won)
    }
}

/// Result of reconciling the turnstile pointer to the actual on-disk hash
/// ([`crate::ManifestStore::reconcile_pointer`]). An out-of-band
/// edit to `servers/*.yaml` (or a boot that loads a disk set the pointer never
/// saw) otherwise leaves the pointer stale, so every later CAS loses and
/// dashboard saves permanently fail. `Advanced` is the case worth
/// surfacing — the pointer was stale and is now re-synced to disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PointerReconcile {
    /// The pointer was absent and has been seeded at the disk hash.
    Seeded,
    /// The pointer already matched the on-disk hash — nothing to do.
    AlreadyInSync,
    /// The pointer was stale and was advanced to the disk hash. `from` is the
    /// stale value it held (the out-of-band signal).
    Advanced { from: String },
    /// The stale pointer changed under us between the read and the CAS — another
    /// replica reconciled or advanced it concurrently. Benign: the pointer is
    /// now some fresh value; the next operation reads it.
    RacedAnotherReplica,
    /// The pointer differs from disk but was advanced very recently (within the
    /// reconcile grace window), so a legitimate writer may be mid-flight: the
    /// write paths CAS the pointer to the new hash BEFORE mirroring the file, so
    /// for the duration of that mirror the pointer is legitimately *ahead* of
    /// disk. Reconciling then would roll the pointer back and undo the writer's
    /// claim — a lost update. We defer instead; the next reload re-checks, by
    /// which time a real writer has finished its mirror (disk == pointer) and a
    /// genuine out-of-band edit has aged past the grace window.
    DeferredInFlight,
}

/// Errors surfaced by the `ManifestStore`. Mirrors `PolicyError`.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("manifest store: {0}")]
    Database(#[source] sqlx::Error),
    /// The targeted subject (bundle id, or `(tenant, version)`) doesn't
    /// exist, or isn't in the state the operation requires (e.g.
    /// publishing a row that isn't a draft).
    #[error("{0}")]
    NotFound(&'static str),
    /// A `status` string read from the DB wasn't one of the CHECK
    /// values. Surfaced as a typed error rather than a panic so a
    /// future migration adding a status can't crash a running gateway
    /// until it picks up matching code.
    #[error("unknown manifest status: {0}")]
    UnknownStatus(String),
}

/// sha256 of a bundle's content, hex-encoded. Public so the importer and
/// the admin endpoints hash the same way the store does.
pub fn content_hash(content: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(content.as_bytes());
    let digest = h.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trips_through_str() {
        for s in [
            ManifestStatus::Draft,
            ManifestStatus::Published,
            ManifestStatus::RolledBack,
        ] {
            // as_str must match the JSON (snake_case) representation so
            // the DB CHECK vocabulary and the serde wire form agree.
            let json = serde_json::to_string(&s).unwrap();
            assert_eq!(json, format!("\"{}\"", s.as_str()));
        }
    }

    #[test]
    fn content_hash_is_stable_and_sensitive() {
        let a = content_hash("- name: example-messages\n  transport: http\n");
        let b = content_hash("- name: example-messages\n  transport: http\n");
        let c = content_hash("- name: other\n  transport: http\n");
        assert_eq!(a, b, "same content ⇒ same hash");
        assert_ne!(a, c, "different content ⇒ different hash");
        assert_eq!(a.len(), 64, "sha256 hex is 64 chars");
    }
}
