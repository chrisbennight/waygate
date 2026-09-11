//! Policy-bundle domain types shared by the `PolicyStore` trait, the
//! Pg impl, and future callers (admin CRUD, the `ReloadableCedar`
//! loader, the policy simulator).
//!
//! All types are `Clone` + `Send + Sync` because the store is invoked
//! from `axum` handlers and `tokio::spawn`-ed reload tasks. The Cedar
//! `content` is policy source, not a secret — policies describe *who
//! may do what*, and are surfaced verbatim in the admin UI.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Lifecycle of a `policy_bundles` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    /// Staged but not eligible to be the active bundle. The gate
    /// never loads a draft.
    Draft,
    /// Eligible to be the tenant's active bundle. The newest
    /// published version wins.
    Published,
    /// Was published, later superseded by a rollback. Retained for
    /// the audit trail; never re-activated.
    RolledBack,
}

impl PolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Published => "published",
            Self::RolledBack => "rolled_back",
        }
    }
}

/// A full policy bundle including its Cedar `content`. Returned by the
/// reads that need the source (the active-bundle load, a single-bundle
/// fetch). The hot-path loader compares `content_hash` to decide
/// whether a recompile is needed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PolicyBundle {
    pub id: Uuid,
    pub tenant_id: String,
    pub version: i32,
    pub status: PolicyStatus,
    /// Full Cedar policy-set source.
    pub content: String,
    /// sha256(content), hex.
    pub content_hash: String,
    /// Optional policy-test cases carried with the bundle (the reserved
    /// `tests JSONB` column, migration 0012). Raw JSON here — the typed
    /// `PolicyTestCase` shape lives in `waygate-admin`, which this
    /// dependency-light store crate must NOT depend on, so the store
    /// stays content-agnostic and only round-trips the column. A publish
    /// gate (waygate-admin) deserializes + runs these against the draft's
    /// Cedar content before mirroring to disk. `None` for a bundle staged
    /// without attached tests.
    #[serde(default)]
    pub tests: Option<serde_json::Value>,
    pub author: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub published_at: Option<OffsetDateTime>,
    pub published_by: Option<String>,
}

/// Identity of an active bundle without its Cedar source. Reload polling uses
/// this projection to detect an unchanged tenant-policy set before fetching
/// and compiling the full bundle contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivePolicyBundleSignature {
    pub tenant_id: String,
    pub content_hash: String,
}

/// A bundle without its (potentially large) Cedar `content` — for the
/// list endpoint, where rendering every version's full source would be
/// wasteful.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PolicyBundleSummary {
    pub id: Uuid,
    pub tenant_id: String,
    pub version: i32,
    pub status: PolicyStatus,
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
pub enum PolicyHistoryFilter {
    Draft,
    PreviouslyPublished,
}

impl PolicyHistoryFilter {
    pub(crate) fn matches(self, status: PolicyStatus) -> bool {
        match self {
            Self::Draft => status == PolicyStatus::Draft,
            Self::PreviouslyPublished => status != PolicyStatus::Draft,
        }
    }
}

/// One bounded page of policy bundle summaries plus the total matching rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBundlePage {
    pub total: u64,
    pub bundles: Vec<PolicyBundleSummary>,
}

/// Errors surfaced by the `PolicyStore`.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy store: {0}")]
    Database(#[source] sqlx::Error),
    /// The targeted subject (bundle id, or `(tenant, version)`)
    /// doesn't exist, or isn't in the state the operation requires
    /// (e.g. publishing a row that isn't a draft).
    #[error("{0}")]
    NotFound(&'static str),
    /// A `status` string read from the DB wasn't one of the CHECK
    /// values. Surfaced as a typed error rather than a panic so a
    /// future migration adding a status can't crash a running gateway
    /// until it picks up the matching code.
    #[error("unknown policy status: {0}")]
    UnknownStatus(String),
}

/// Cross-replica write turnstile pointer: the canonical hash of the
/// CURRENT live on-disk policy set, plus who/when last advanced it. One row per
/// tenant in `policy_pointer`. Coordination state, not the boot source — see the
/// migration `0041_policy_pointer.sql`. The policy analogue of
/// `waygate_manifest_store::ManifestPointer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPointer {
    pub tenant_id: String,
    pub current_hash: String,
    pub updated_at: OffsetDateTime,
    pub updated_by: Option<String>,
}

/// Result of a turnstile compare-and-swap ([`crate::PolicyStore::cas_pointer`]).
/// `Won` ⇒ this writer atomically advanced the pointer from its base hash and is
/// the one allowed to mirror the bundle to disk; `Lost` ⇒ the live hash no longer
/// matches the base the writer edited from (another replica advanced it first),
/// so the write must be refused with "reload and retry". Mirrors
/// `waygate_manifest_store::TurnstileOutcome`.
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
/// ([`crate::PolicyStore::reconcile_pointer`]). An out-of-band edit to
/// `policies/*.cedar` — or a boot/restart that loads a disk set the persisted
/// pointer never saw (a git deploy: `seed_pointer` is `ON CONFLICT DO NOTHING`,
/// so it leaves the stale row) — otherwise leaves the pointer stale, so every
/// later `cas_pointer` from the current disk hash loses and dashboard/API policy
/// writes permanently fail. `Advanced` is the
/// case worth surfacing. Mirrors `waygate_manifest_store::PointerReconcile`.
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

/// sha256 of a bundle's Cedar source, hex-encoded. Public so the
/// importer and admin endpoints compute the hash the same way the
/// store does.
pub fn content_hash(content: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(content.as_bytes());
    let digest = h.finalize();
    // Hex-encode by hand — avoids a `hex` crate just for this; `sha2
    // 0.11`'s finalize returns a generic byte array without `LowerHex`.
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
            PolicyStatus::Draft,
            PolicyStatus::Published,
            PolicyStatus::RolledBack,
        ] {
            // as_str must match the JSON (snake_case) representation so
            // the DB CHECK vocabulary and the serde wire form agree.
            let json = serde_json::to_string(&s).unwrap();
            assert_eq!(json, format!("\"{}\"", s.as_str()));
        }
    }

    #[test]
    fn content_hash_is_stable_and_sensitive() {
        let a = content_hash("permit(principal, action, resource);");
        let b = content_hash("permit(principal, action, resource);");
        let c = content_hash("forbid(principal, action, resource);");
        assert_eq!(a, b, "same content ⇒ same hash");
        assert_ne!(a, c, "different content ⇒ different hash");
        assert_eq!(a.len(), 64, "sha256 hex is 64 chars");
    }
}
