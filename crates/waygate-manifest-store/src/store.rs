//! `ManifestStore` trait + Postgres impl.
//!
//! A byte-for-byte port of `waygate_policy::PgPolicyStore` against the
//! `server_manifests` table (migration 0037), with `content` holding the
//! upstream-manifest set as a YAML sequence instead of a Cedar policy
//! set. The boot and SIGHUP recovery path uses `active_bundle`, and
//! `--import-server-bundle` seeds via `create_draft` + `publish`; the
//! remaining methods are called by the admin REST surface
//! (`waygate-admin`'s `manifest_bundles.rs`). The full trait is
//! defined now — pub trait/impl items are part of the public API, not
//! dead code.
//!
//! Uses runtime `sqlx::query(...)` + `.bind()` + `row.get(...)` (NOT the
//! compile-checked `sqlx::query!` macro), exactly like `PgPolicyStore`,
//! so the crate compiles in CI with no live DB / offline data.

use std::sync::Arc;

use async_trait::async_trait;
use sqlx::postgres::PgPool;
use sqlx::Row;
use uuid::Uuid;

use crate::types::{
    content_hash, ManifestBundle, ManifestBundlePage, ManifestBundleSummary, ManifestError,
    ManifestHistoryFilter, ManifestPointer, ManifestStatus, PointerReconcile, ReplicaHeartbeat,
    TurnstileOutcome,
};

/// Decoupled store surface so callers (the boot loader, the SIGHUP
/// reload task, the admin REST endpoints) don't reach for the Postgres pool
/// directly. Tests implement a fake; production wires [`PgManifestStore`].
#[async_trait]
pub trait ManifestStore: Send + Sync + 'static {
    /// The tenant's active manifest bundle: the **most recently
    /// published** one (`ORDER BY published_at DESC`, `version DESC`
    /// only as a same-instant tiebreak). Hot path — boot + SIGHUP
    /// consult it, not per call. `NotFound` when the tenant has no
    /// published bundle (a fresh deploy before `--import-server-bundle`).
    async fn active_bundle(&self, tenant_id: &str) -> Result<ManifestBundle, ManifestError>;

    /// Every bundle for the tenant, newest version first, without the
    /// (large) `content`. Use [`Self::active_bundle`] / [`Self::get`]
    /// when the source is needed.
    async fn list_bundles(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<ManifestBundleSummary>, ManifestError>;

    /// A bounded page of draft or previously-published history. Production
    /// stores must apply the filter, limit, and offset in the database. The
    /// default keeps existing test fakes source-compatible.
    async fn list_bundles_page(
        &self,
        tenant_id: &str,
        filter: ManifestHistoryFilter,
        limit: u32,
        offset: u32,
    ) -> Result<ManifestBundlePage, ManifestError> {
        let bundles: Vec<_> = self
            .list_bundles(tenant_id)
            .await?
            .into_iter()
            .filter(|bundle| filter.matches(bundle.status))
            .collect();
        let total = u64::try_from(bundles.len()).unwrap_or(u64::MAX);
        let offset = usize::try_from(offset).unwrap_or(usize::MAX);
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        Ok(ManifestBundlePage {
            total,
            bundles: bundles.into_iter().skip(offset).take(limit).collect(),
        })
    }

    /// A single bundle by id, scoped to the caller's tenant. Returns the
    /// full `ManifestBundle` (including `content`) so the dashboard editor
    /// can pre-fill from any version. Tenant predicate at the read
    /// boundary; `NotFound` for an absent or different-tenant id.
    async fn get(&self, tenant_id: &str, bundle_id: Uuid) -> Result<ManifestBundle, ManifestError>;

    /// A single previously-published bundle by `version` (not a draft), with
    /// its full `content` — so a rollback can claim the turnstile + mirror the
    /// target's content to disk BEFORE the `rollback_to` ledger transition.
    /// `NotFound` for an absent / draft-only / wrong-tenant
    /// version. Default impl returns `NotFound` for stores that don't index by
    /// version (the test fakes that don't exercise rollback).
    async fn get_by_version(
        &self,
        _tenant_id: &str,
        _version: i32,
    ) -> Result<ManifestBundle, ManifestError> {
        Err(ManifestError::NotFound(
            "get_by_version not supported by this store",
        ))
    }

    /// Append a new `draft` bundle at the next version for the tenant.
    /// The version is assigned atomically (`MAX(version)+1` in the
    /// INSERT); a concurrent race hits `UNIQUE(tenant_id, version)`.
    async fn create_draft(
        &self,
        tenant_id: &str,
        content: &str,
        author: Option<&str>,
    ) -> Result<ManifestBundle, ManifestError>;

    /// Promote a `draft` bundle to `published`, stamping `published_at` /
    /// `published_by`. Conditional on the row still being a draft owned
    /// by this tenant, so a second publish or a cross-tenant attempt
    /// returns `NotFound`. Doesn't demote prior published versions — the
    /// active bundle is simply the newest published one.
    async fn publish(
        &self,
        tenant_id: &str,
        bundle_id: Uuid,
        publisher: &str,
    ) -> Result<ManifestBundle, ManifestError>;

    /// Roll the active manifest set back to a previously-published
    /// `version`'s content by re-publishing it as a NEW bundle at the
    /// next version (append-only roll-forward). The target must exist and
    /// have been published (`published`/`rolled_back`); a never-published
    /// draft is rejected with `NotFound`.
    async fn rollback_to(
        &self,
        tenant_id: &str,
        version: i32,
        actor: &str,
    ) -> Result<ManifestBundle, ManifestError>;

    /// Bulk-delete every bundle for a tenant (drafts + published).
    /// Mirrors the policy store's tenant-cleanup hook so a re-created
    /// tenant id starts with an empty bundle history. Returns the row
    /// count for audit/logging.
    async fn delete_all_for_tenant(&self, tenant_id: &str) -> Result<u64, ManifestError>;

    // --- Cross-replica write turnstile --------------------------------------

    /// Read the turnstile pointer for the tenant: the hash of the current
    /// live on-disk manifest set. `None` when it has not been seeded yet
    /// (a fresh deploy before the first boot seed / write).
    async fn read_pointer(&self, tenant_id: &str)
        -> Result<Option<ManifestPointer>, ManifestError>;

    /// Seed the turnstile pointer at `hash` IF absent (`ON CONFLICT DO
    /// NOTHING`). Idempotent and never clobbers a pointer another replica
    /// may have advanced — boot and `--import-server-bundle` call it to
    /// establish the pointer at the current live hash without racing a
    /// concurrent writer.
    async fn seed_pointer(&self, tenant_id: &str, hash: &str) -> Result<(), ManifestError>;

    /// Compare-and-swap the turnstile pointer from `expected_hash` to
    /// `new_hash`. Atomic conditional UPDATE: `Won` when this writer
    /// advanced it (rows_affected == 1), `Lost` when the live hash no
    /// longer matched `expected_hash` (another replica advanced it first,
    /// or the pointer is absent). Callers run this BEFORE writing the file,
    /// so only the winner ever renames — the clobber is prevented, not just
    /// detected.
    async fn cas_pointer(
        &self,
        tenant_id: &str,
        expected_hash: &str,
        new_hash: &str,
        actor: &str,
    ) -> Result<TurnstileOutcome, ManifestError>;

    /// Doorbell: fire a Postgres `NOTIFY` on the
    /// `mcp_manifest_reload` channel after a successful write + ledger append,
    /// carrying the new content hash as the payload. Every gateway replica
    /// `LISTEN`s on that channel and re-reads the shared servers dir on
    /// receipt, so a dashboard edit on one replica propagates to the fleet
    /// without waiting for the poll backstop. Best-effort at the call site: a
    /// notify failure is logged, never fails the edit — the poll still
    /// converges.
    ///
    /// Default no-op: a non-Postgres store (the test fakes, a future file-only
    /// store) has no doorbell, so it inherits this and the poll backstop is the
    /// only propagation path. [`PgManifestStore`] overrides it with a real
    /// `pg_notify`.
    async fn notify_reload(&self, _hash: &str) -> Result<(), ManifestError> {
        Ok(())
    }

    /// Reconcile the turnstile pointer to the actual on-disk hash. An
    /// out-of-band edit to `servers/*.yaml` — or a boot that loads a
    /// disk set the pointer never saw — otherwise leaves the pointer stale, so
    /// every later `cas_pointer` from the *current* disk hash loses
    /// (`TurnstileOutcome::Lost`) and dashboard saves permanently fail.
    /// Callers run this on boot (clean disk load), SIGHUP/doorbell
    /// reload, and dashboard Reload so the pointer tracks disk.
    ///
    /// ## Why it must not blindly CAS the pointer to disk
    ///
    /// The write paths deliberately advance the pointer BEFORE mirroring the
    /// file (`cas_pointer(disk -> new)` then `mirror_manifest_set_to_disk`):
    /// that ordering is what prevents the lost update (only the CAS winner ever
    /// renames). So for the duration of a writer's mirror the pointer is
    /// legitimately *ahead* of disk — pointer == new, disk still == old. A
    /// snapshot taken in that window is indistinguishable, by hash alone, from a
    /// genuine out-of-band staleness where the pointer is *behind* disk.
    /// Treating every `pointer != disk` as stale and CASing the observed pointer
    /// back to the disk hash would roll back a mid-flight writer and reintroduce
    /// the very lost update the turnstile exists to prevent.
    ///
    /// The distinguisher is TIME, not the hashes: a mid-flight writer converges
    /// disk to the pointer within its mirror (a few atomic renames — sub-second
    /// even on NFS), whereas a true out-of-band divergence persists. So we only
    /// reconcile a pointer whose `updated_at` is older than [`RECONCILE_GRACE`],
    /// a window chosen to comfortably exceed any mirror duration (plus
    /// gateway↔DB clock skew on NTP-synced hosts). A pointer advanced more
    /// recently than that is treated as possibly-in-flight and DEFERRED — the
    /// next reload re-checks, by which point a real writer has finished
    /// (disk == pointer ⇒ `AlreadyInSync`) and a genuine out-of-band edit has
    /// aged past the grace window (⇒ `Advanced`).
    ///
    /// Still race-safe in the act-now branch: the CAS is conditional on the
    /// value we read, so a writer's advance landing between the read and the CAS
    /// just makes this lose (`RacedAnotherReplica`), never clobbering it.
    ///
    /// Provided method composing [`Self::read_pointer`], [`Self::seed_pointer`],
    /// and [`Self::cas_pointer`], so every store (Postgres + the test fakes)
    /// inherits it and it is covered by the trait-level unit tests.
    async fn reconcile_pointer(
        &self,
        tenant_id: &str,
        disk_hash: &str,
        actor: &str,
    ) -> Result<PointerReconcile, ManifestError> {
        match self.read_pointer(tenant_id).await? {
            None => {
                self.seed_pointer(tenant_id, disk_hash).await?;
                Ok(PointerReconcile::Seeded)
            }
            Some(p) if p.current_hash == disk_hash => Ok(PointerReconcile::AlreadyInSync),
            Some(p) => {
                // Defer if the pointer was advanced within the grace window — a
                // writer may have CASed it and not yet finished its mirror, so
                // it is legitimately ahead of disk, not stale.
                let age = time::OffsetDateTime::now_utc() - p.updated_at;
                if age < RECONCILE_GRACE {
                    return Ok(PointerReconcile::DeferredInFlight);
                }
                match self
                    .cas_pointer(tenant_id, &p.current_hash, disk_hash, actor)
                    .await?
                {
                    TurnstileOutcome::Won => Ok(PointerReconcile::Advanced {
                        from: p.current_hash,
                    }),
                    TurnstileOutcome::Lost => Ok(PointerReconcile::RacedAnotherReplica),
                }
            }
        }
    }

    /// Record the current on-disk manifest set as a `published` ledger bundle
    /// attributed to [`FILESYSTEM_ACTOR`]. Boot/reload call
    /// this when they detect the on-disk set has drifted from the latest ledger
    /// snapshot — i.e. an out-of-band edit to `servers/*.yaml` that bypassed the
    /// dashboard. Capturing it closes the bypass (the out-of-band state becomes
    /// visible in history and is rollback-able) and gives free convergence
    /// monitoring (every divergence lands a row).
    ///
    /// `content` is the caller's canonical serialization of the on-disk set
    /// (`serialize_manifest_set(load_manifests(dir))`), so `content_hash(content)`
    /// is the canonical disk hash. The store is content-agnostic — it does not
    /// canonicalize (it has no manifest-types dependency); the caller owns
    /// the "is this out-of-band?" comparison.
    ///
    /// Idempotent against the **ACTIVE** snapshot: returns `Ok(None)` only if the
    /// latest published bundle already has this content hash (we, or another
    /// replica that won the race, already made it the latest). A match on an
    /// *older* version must NOT skip — a disk revert to an old version's content
    /// (active is B, disk is an earlier A that still exists in history) has to
    /// become the new latest snapshot or the gateway never converges and every
    /// reload re-detects the same drift. Else `Ok(Some(bundle))` for
    /// the new row.
    ///
    /// The active-row comparison works across the canonical/raw split because a
    /// `filesystem` row stores the canonical content the caller passes here, so
    /// its `content_hash` equals `content_hash(content)`; and when the active is
    /// a normally-published (possibly non-canonical) row, the caller has already
    /// established via its canonical drift check that it differs from disk, so
    /// this raw comparison also differs and correctly proceeds.
    ///
    /// Best-effort against a multi-replica race: two replicas detecting the same
    /// out-of-band edit at the same instant can both pass the active check
    /// (before either's row is the active) and both insert at `MAX(version)+1`;
    /// one wins and the other gets a `UNIQUE(tenant, version)` error (surfaced to
    /// the caller, which logs best-effort) or a duplicate `filesystem` row at the
    /// same content. Either way it converges (the active becomes the disk
    /// content). A future `PgManifestStore` override could collapse this to one
    /// atomic statement.
    ///
    /// Provided method composing [`Self::active_bundle`], [`Self::create_draft`],
    /// and [`Self::publish`], so every store inherits it and it is covered by
    /// the trait-level unit tests.
    async fn record_filesystem_snapshot(
        &self,
        tenant_id: &str,
        content: &str,
    ) -> Result<Option<ManifestBundle>, ManifestError> {
        let hash = content_hash(content);
        // Idempotent against the ACTIVE (latest published) snapshot only — not
        // any historical version. A fresh deploy with no active
        // bundle proceeds to record the first snapshot.
        match self.active_bundle(tenant_id).await {
            Ok(active) if active.content_hash == hash => return Ok(None),
            Ok(_) => {}
            Err(ManifestError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
        let draft = self
            .create_draft(tenant_id, content, Some(FILESYSTEM_ACTOR))
            .await?;
        let published = self.publish(tenant_id, draft.id, FILESYSTEM_ACTOR).await?;
        Ok(Some(published))
    }

    // --- Fleet heartbeat (observability) ------------------------------------

    /// Record this replica's current heartbeat — the config `version` (None when
    /// the on-disk set is uncommitted/out-of-band) and `content_hash` it has
    /// loaded — in `fleet_replicas`, upserting on `replica_id`. Called on every
    /// reload (boot + the doorbell/poll/SIGHUP loop) so the dashboard fleet
    /// roll-up sees a fresh `updated_at`. Best-effort at the call site.
    ///
    /// Default no-op: a non-Postgres store (the test fakes, a future file-only
    /// store) has no heartbeat table, so the fleet view is simply empty.
    /// [`PgManifestStore`] overrides it with a real UPSERT.
    async fn upsert_replica_heartbeat(
        &self,
        _replica_id: &str,
        _tenant_id: &str,
        _version: Option<i32>,
        _content_hash: &str,
    ) -> Result<(), ManifestError> {
        Ok(())
    }

    /// Refresh ONLY this replica's heartbeat timestamp, leaving its recorded
    /// version + hash untouched. Called when a reload
    /// FAILS (unreadable / refused on-disk set): the replica is still alive and
    /// serving the PREVIOUS set, so its liveness must keep ticking even though
    /// there's no new config to record — otherwise the fleet row ages past the
    /// staleness window and is wrongly shown down. A no-op when the replica has
    /// no prior heartbeat row (rows-affected 0). Default no-op (no table without
    /// a DB); [`PgManifestStore`] overrides it.
    async fn touch_replica_heartbeat(&self, _replica_id: &str) -> Result<(), ManifestError> {
        Ok(())
    }

    /// List the fleet's replica heartbeats for a tenant, newest check-in first,
    /// for the dashboard roll-up. Default empty (no heartbeat table without a
    /// database); [`PgManifestStore`] overrides it.
    async fn list_replica_heartbeats(
        &self,
        _tenant_id: &str,
    ) -> Result<Vec<ReplicaHeartbeat>, ManifestError> {
        Ok(Vec::new())
    }
}

/// Author/`published_by` attribution for a ledger bundle the gateway itself
/// synthesized from an out-of-band on-disk edit, distinct from any human
/// principal. Surfaced in the dashboard history so an
/// operator can tell a `filesystem` convergence row from a dashboard publish.
pub const FILESYSTEM_ACTOR: &str = "filesystem";

/// How long the turnstile pointer must have been settled (unchanged) before
/// [`ManifestStore::reconcile_pointer`] will treat a `pointer != disk`
/// divergence as a genuine out-of-band edit rather than a writer mid-flight.
/// It must exceed the longest realistic file-mirror duration (a
/// handful of atomic `rename`s over NFS — well under a second) plus the
/// gateway↔Postgres clock skew on NTP-synced hosts. 15s is comfortably above
/// both while staying under the manifest poll backstop so a deferred reconcile
/// is retried promptly on the next tick.
pub const RECONCILE_GRACE: time::Duration = time::Duration::seconds(15);

/// The Postgres channel the doorbell uses. `NOTIFY`/`LISTEN`
/// channel identifiers can't be bound parameters, so it is a single shared
/// constant rather than interpolated per call.
pub const MANIFEST_RELOAD_CHANNEL: &str = "mcp_manifest_reload";

/// Type-erased handle, matching every other store in this workspace
/// (`SharedPolicyStore`, `SharedCatalogStore`).
pub type SharedManifestStore = Arc<dyn ManifestStore>;

/// Postgres-backed [`ManifestStore`]. One instance per gateway boot;
/// cheaply `Clone`-able because `PgPool` is internally an `Arc`.
#[derive(Clone)]
pub struct PgManifestStore {
    pool: PgPool,
}

impl PgManifestStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> PgPool {
        self.pool.clone()
    }
}

/// Columns selected for a full [`ManifestBundle`]. Kept in one place so
/// the active-bundle / create-draft / publish queries stay in sync.
const BUNDLE_COLS: &str = "id, tenant_id, version, status, content, content_hash, \
                           author, created_at, published_at, published_by";

#[async_trait]
impl ManifestStore for PgManifestStore {
    async fn active_bundle(&self, tenant_id: &str) -> Result<ManifestBundle, ManifestError> {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {BUNDLE_COLS} \
               FROM server_manifests \
              WHERE tenant_id = $1 AND status = 'published' \
              ORDER BY published_at DESC NULLS LAST, version DESC \
              LIMIT 1"
        )))
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(ManifestError::Database)?;
        match row {
            Some(r) => bundle_from_row(&r),
            None => Err(ManifestError::NotFound(
                "no published manifest bundle for tenant",
            )),
        }
    }

    async fn list_bundles(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<ManifestBundleSummary>, ManifestError> {
        let rows = sqlx::query(
            "SELECT id, tenant_id, version, status, content_hash, \
                    author, created_at, published_at, published_by \
               FROM server_manifests \
              WHERE tenant_id = $1 \
              ORDER BY version DESC",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(ManifestError::Database)?;
        rows.iter().map(summary_from_row).collect()
    }

    async fn list_bundles_page(
        &self,
        tenant_id: &str,
        filter: ManifestHistoryFilter,
        limit: u32,
        offset: u32,
    ) -> Result<ManifestBundlePage, ManifestError> {
        let drafts = filter == ManifestHistoryFilter::Draft;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) \
               FROM server_manifests \
              WHERE tenant_id = $1 \
                AND (($2 AND status = 'draft') OR (NOT $2 AND status <> 'draft'))",
        )
        .bind(tenant_id)
        .bind(drafts)
        .fetch_one(&self.pool)
        .await
        .map_err(ManifestError::Database)?;
        let rows = sqlx::query(
            "SELECT id, tenant_id, version, status, content_hash, \
                    author, created_at, published_at, published_by \
               FROM server_manifests \
              WHERE tenant_id = $1 \
                AND (($2 AND status = 'draft') OR (NOT $2 AND status <> 'draft')) \
              ORDER BY version DESC \
              LIMIT $3 OFFSET $4",
        )
        .bind(tenant_id)
        .bind(drafts)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(ManifestError::Database)?;
        Ok(ManifestBundlePage {
            total: u64::try_from(total).expect("COUNT(*) is nonnegative"),
            bundles: rows
                .iter()
                .map(summary_from_row)
                .collect::<Result<_, _>>()?,
        })
    }

    async fn get(&self, tenant_id: &str, bundle_id: Uuid) -> Result<ManifestBundle, ManifestError> {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {BUNDLE_COLS} \
               FROM server_manifests \
              WHERE id = $1 AND tenant_id = $2 \
              LIMIT 1"
        )))
        .bind(bundle_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(ManifestError::Database)?;
        match row {
            Some(r) => bundle_from_row(&r),
            None => Err(ManifestError::NotFound(
                "no manifest bundle with that id in tenant",
            )),
        }
    }

    async fn get_by_version(
        &self,
        tenant_id: &str,
        version: i32,
    ) -> Result<ManifestBundle, ManifestError> {
        // A rollback target must be a previously-published version (not a
        // never-published draft), matching `rollback_to`'s `status <> 'draft'`.
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {BUNDLE_COLS} \
               FROM server_manifests \
              WHERE tenant_id = $1 AND version = $2 AND status <> 'draft' \
              LIMIT 1"
        )))
        .bind(tenant_id)
        .bind(version)
        .fetch_optional(&self.pool)
        .await
        .map_err(ManifestError::Database)?;
        match row {
            Some(r) => bundle_from_row(&r),
            None => Err(ManifestError::NotFound(
                "no previously-published manifest bundle at that version in tenant",
            )),
        }
    }

    async fn create_draft(
        &self,
        tenant_id: &str,
        content: &str,
        author: Option<&str>,
    ) -> Result<ManifestBundle, ManifestError> {
        let hash = content_hash(content);
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO server_manifests \
                 (id, tenant_id, version, status, content, content_hash, author) \
             VALUES ($1, $2, \
                     (SELECT COALESCE(MAX(version), 0) + 1 \
                        FROM server_manifests WHERE tenant_id = $2), \
                     'draft', $3, $4, $5) \
             RETURNING {BUNDLE_COLS}"
        )))
        .bind(Uuid::now_v7())
        .bind(tenant_id)
        .bind(content)
        .bind(&hash)
        .bind(author)
        .fetch_one(&self.pool)
        .await
        .map_err(ManifestError::Database)?;
        bundle_from_row(&row)
    }

    async fn publish(
        &self,
        tenant_id: &str,
        bundle_id: Uuid,
        publisher: &str,
    ) -> Result<ManifestBundle, ManifestError> {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "UPDATE server_manifests \
                SET status = 'published', published_at = now(), published_by = $3 \
              WHERE id = $1 AND tenant_id = $2 AND status = 'draft' \
            RETURNING {BUNDLE_COLS}"
        )))
        .bind(bundle_id)
        .bind(tenant_id)
        .bind(publisher)
        .fetch_optional(&self.pool)
        .await
        .map_err(ManifestError::Database)?;
        match row {
            Some(r) => bundle_from_row(&r),
            None => Err(ManifestError::NotFound(
                "no draft manifest bundle with that id in tenant",
            )),
        }
    }

    async fn rollback_to(
        &self,
        tenant_id: &str,
        version: i32,
        actor: &str,
    ) -> Result<ManifestBundle, ManifestError> {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO server_manifests \
                 (id, tenant_id, version, status, content, content_hash, \
                  author, published_at, published_by) \
             SELECT $1, tenant_id, \
                    (SELECT COALESCE(MAX(version), 0) + 1 \
                       FROM server_manifests WHERE tenant_id = $2), \
                    'published', content, content_hash, $4, now(), $4 \
               FROM server_manifests \
              WHERE tenant_id = $2 AND version = $3 AND status <> 'draft' \
            RETURNING {BUNDLE_COLS}"
        )))
        .bind(Uuid::now_v7())
        .bind(tenant_id)
        .bind(version)
        .bind(actor)
        .fetch_optional(&self.pool)
        .await
        .map_err(ManifestError::Database)?;
        match row {
            Some(r) => bundle_from_row(&r),
            None => Err(ManifestError::NotFound(
                "no published manifest bundle at that version in tenant",
            )),
        }
    }

    async fn delete_all_for_tenant(&self, tenant_id: &str) -> Result<u64, ManifestError> {
        let result = sqlx::query("DELETE FROM server_manifests WHERE tenant_id = $1")
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(ManifestError::Database)?;
        Ok(result.rows_affected())
    }

    async fn read_pointer(
        &self,
        tenant_id: &str,
    ) -> Result<Option<ManifestPointer>, ManifestError> {
        let row = sqlx::query(
            "SELECT tenant_id, current_hash, updated_at, updated_by \
               FROM server_manifest_pointer WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(ManifestError::Database)?;
        Ok(row.map(|r| ManifestPointer {
            tenant_id: r.get("tenant_id"),
            current_hash: r.get("current_hash"),
            updated_at: r.get("updated_at"),
            updated_by: r.get("updated_by"),
        }))
    }

    async fn seed_pointer(&self, tenant_id: &str, hash: &str) -> Result<(), ManifestError> {
        // ON CONFLICT DO NOTHING: idempotent seed. Establishes the pointer at
        // the current live hash on first boot/import; a no-op if another
        // replica already seeded or advanced it, so it never clobbers a
        // concurrent writer's value.
        sqlx::query(
            "INSERT INTO server_manifest_pointer (tenant_id, current_hash) \
             VALUES ($1, $2) ON CONFLICT (tenant_id) DO NOTHING",
        )
        .bind(tenant_id)
        .bind(hash)
        .execute(&self.pool)
        .await
        .map_err(ManifestError::Database)?;
        Ok(())
    }

    async fn cas_pointer(
        &self,
        tenant_id: &str,
        expected_hash: &str,
        new_hash: &str,
        actor: &str,
    ) -> Result<TurnstileOutcome, ManifestError> {
        // Atomic conditional UPDATE. tenant_id is the PK, so at most one row
        // matches: rows_affected is 1 (won) or 0 (the live hash moved off
        // `expected_hash`, or the pointer isn't seeded). No transaction
        // needed — a single statement is the serialization point.
        let result = sqlx::query(
            "UPDATE server_manifest_pointer \
                SET current_hash = $3, updated_at = now(), updated_by = $4 \
              WHERE tenant_id = $1 AND current_hash = $2",
        )
        .bind(tenant_id)
        .bind(expected_hash)
        .bind(new_hash)
        .bind(actor)
        .execute(&self.pool)
        .await
        .map_err(ManifestError::Database)?;
        Ok(if result.rows_affected() == 1 {
            TurnstileOutcome::Won
        } else {
            TurnstileOutcome::Lost
        })
    }

    async fn notify_reload(&self, hash: &str) -> Result<(), ManifestError> {
        // pg_notify(channel, payload): the channel can't be a bound param, so
        // it is the compile-time constant; the payload (hash) is bound.
        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(MANIFEST_RELOAD_CHANNEL)
            .bind(hash)
            .execute(&self.pool)
            .await
            .map_err(ManifestError::Database)?;
        Ok(())
    }

    async fn upsert_replica_heartbeat(
        &self,
        replica_id: &str,
        tenant_id: &str,
        version: Option<i32>,
        content_hash: &str,
    ) -> Result<(), ManifestError> {
        sqlx::query(
            "INSERT INTO fleet_replicas \
                 (replica_id, tenant_id, version, content_hash, updated_at) \
             VALUES ($1, $2, $3, $4, now()) \
             ON CONFLICT (replica_id) DO UPDATE \
                SET tenant_id = $2, version = $3, content_hash = $4, updated_at = now()",
        )
        .bind(replica_id)
        .bind(tenant_id)
        .bind(version)
        .bind(content_hash)
        .execute(&self.pool)
        .await
        .map_err(ManifestError::Database)?;
        Ok(())
    }

    async fn touch_replica_heartbeat(&self, replica_id: &str) -> Result<(), ManifestError> {
        // Liveness-only: refresh updated_at, leave version/content_hash as the
        // last successful reload recorded them. No-op (0 rows) if absent.
        sqlx::query("UPDATE fleet_replicas SET updated_at = now() WHERE replica_id = $1")
            .bind(replica_id)
            .execute(&self.pool)
            .await
            .map_err(ManifestError::Database)?;
        Ok(())
    }

    async fn list_replica_heartbeats(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<ReplicaHeartbeat>, ManifestError> {
        let rows = sqlx::query(
            "SELECT replica_id, tenant_id, version, content_hash, updated_at \
               FROM fleet_replicas WHERE tenant_id = $1 ORDER BY updated_at DESC",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(ManifestError::Database)?;
        Ok(rows
            .into_iter()
            .map(|r| ReplicaHeartbeat {
                replica_id: r.get("replica_id"),
                tenant_id: r.get("tenant_id"),
                version: r.get("version"),
                content_hash: r.get("content_hash"),
                updated_at: r.get("updated_at"),
            })
            .collect())
    }
}

fn parse_status(s: &str) -> Result<ManifestStatus, ManifestError> {
    Ok(match s {
        "draft" => ManifestStatus::Draft,
        "published" => ManifestStatus::Published,
        "rolled_back" => ManifestStatus::RolledBack,
        other => return Err(ManifestError::UnknownStatus(other.to_owned())),
    })
}

fn bundle_from_row(r: &sqlx::postgres::PgRow) -> Result<ManifestBundle, ManifestError> {
    Ok(ManifestBundle {
        id: r.get("id"),
        tenant_id: r.get("tenant_id"),
        version: r.get("version"),
        status: parse_status(r.get::<&str, _>("status"))?,
        content: r.get("content"),
        content_hash: r.get("content_hash"),
        author: r.get("author"),
        created_at: r.get("created_at"),
        published_at: r.get("published_at"),
        published_by: r.get("published_by"),
    })
}

fn summary_from_row(r: &sqlx::postgres::PgRow) -> Result<ManifestBundleSummary, ManifestError> {
    Ok(ManifestBundleSummary {
        id: r.get("id"),
        tenant_id: r.get("tenant_id"),
        version: r.get("version"),
        status: parse_status(r.get::<&str, _>("status"))?,
        content_hash: r.get("content_hash"),
        author: r.get("author"),
        created_at: r.get("created_at"),
        published_at: r.get("published_at"),
        published_by: r.get("published_by"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_status_accepts_check_vocabulary() {
        assert_eq!(parse_status("draft").unwrap(), ManifestStatus::Draft);
        assert_eq!(
            parse_status("published").unwrap(),
            ManifestStatus::Published
        );
        assert_eq!(
            parse_status("rolled_back").unwrap(),
            ManifestStatus::RolledBack
        );
    }

    #[test]
    fn parse_status_rejects_unknown() {
        match parse_status("archived") {
            Err(ManifestError::UnknownStatus(s)) => assert_eq!(s, "archived"),
            other => panic!("expected UnknownStatus, got {other:?}"),
        }
    }

    /// Stateful in-memory fake modeling ONLY the turnstile pointer, to exercise
    /// the provided `reconcile_pointer` logic without a database. Every other
    /// `ManifestStore` method is `unimplemented!()` — `reconcile_pointer` calls
    /// only read/seed/cas. `updated_at` is what `read_pointer` reports (drives
    /// the grace check); `cas_always_loses` simulates a concurrent advance
    /// between the read and the CAS (the `RacedAnotherReplica` path).
    struct PointerFake {
        pointer: std::sync::Mutex<Option<String>>,
        updated_at: time::OffsetDateTime,
        cas_always_loses: bool,
    }

    impl PointerFake {
        /// `updated_at` defaults to UNIX_EPOCH (far past the grace window) so
        /// the pointer is treated as settled; the defer test overrides it.
        fn new(initial: Option<&str>) -> Self {
            Self {
                pointer: std::sync::Mutex::new(initial.map(str::to_owned)),
                updated_at: time::OffsetDateTime::UNIX_EPOCH,
                cas_always_loses: false,
            }
        }
        fn current(&self) -> Option<String> {
            self.pointer.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl ManifestStore for PointerFake {
        async fn read_pointer(
            &self,
            _tenant_id: &str,
        ) -> Result<Option<ManifestPointer>, ManifestError> {
            Ok(self.current().map(|h| ManifestPointer {
                tenant_id: "default".into(),
                current_hash: h,
                updated_at: self.updated_at,
                updated_by: None,
            }))
        }
        async fn seed_pointer(&self, _tenant_id: &str, hash: &str) -> Result<(), ManifestError> {
            // INSERT ON CONFLICT DO NOTHING: only establishes an absent pointer.
            let mut p = self.pointer.lock().unwrap();
            if p.is_none() {
                *p = Some(hash.to_owned());
            }
            Ok(())
        }
        async fn cas_pointer(
            &self,
            _tenant_id: &str,
            expected_hash: &str,
            new_hash: &str,
            _actor: &str,
        ) -> Result<TurnstileOutcome, ManifestError> {
            if self.cas_always_loses {
                return Ok(TurnstileOutcome::Lost);
            }
            let mut p = self.pointer.lock().unwrap();
            if p.as_deref() == Some(expected_hash) {
                *p = Some(new_hash.to_owned());
                Ok(TurnstileOutcome::Won)
            } else {
                Ok(TurnstileOutcome::Lost)
            }
        }
        async fn active_bundle(&self, _t: &str) -> Result<ManifestBundle, ManifestError> {
            unimplemented!("not used by reconcile_pointer")
        }
        async fn list_bundles(
            &self,
            _t: &str,
        ) -> Result<Vec<ManifestBundleSummary>, ManifestError> {
            unimplemented!("not used by reconcile_pointer")
        }
        async fn get(&self, _t: &str, _id: Uuid) -> Result<ManifestBundle, ManifestError> {
            unimplemented!("not used by reconcile_pointer")
        }
        async fn create_draft(
            &self,
            _t: &str,
            _content: &str,
            _author: Option<&str>,
        ) -> Result<ManifestBundle, ManifestError> {
            unimplemented!("not used by reconcile_pointer")
        }
        async fn publish(
            &self,
            _t: &str,
            _id: Uuid,
            _publisher: &str,
        ) -> Result<ManifestBundle, ManifestError> {
            unimplemented!("not used by reconcile_pointer")
        }
        async fn rollback_to(
            &self,
            _t: &str,
            _version: i32,
            _actor: &str,
        ) -> Result<ManifestBundle, ManifestError> {
            unimplemented!("not used by reconcile_pointer")
        }
        async fn delete_all_for_tenant(&self, _t: &str) -> Result<u64, ManifestError> {
            unimplemented!("not used by reconcile_pointer")
        }
    }

    #[tokio::test]
    async fn reconcile_seeds_an_absent_pointer() {
        let fake = PointerFake::new(None);
        let out = fake
            .reconcile_pointer("default", "H", "filesystem")
            .await
            .unwrap();
        assert_eq!(out, PointerReconcile::Seeded);
        assert_eq!(fake.current().as_deref(), Some("H"));
    }

    #[tokio::test]
    async fn reconcile_is_a_noop_when_already_in_sync() {
        let fake = PointerFake::new(Some("H"));
        let out = fake
            .reconcile_pointer("default", "H", "filesystem")
            .await
            .unwrap();
        assert_eq!(out, PointerReconcile::AlreadyInSync);
        assert_eq!(fake.current().as_deref(), Some("H"), "pointer untouched");
    }

    #[tokio::test]
    async fn reconcile_advances_a_stale_pointer_to_disk() {
        // Out-of-band-edit case: an out-of-band edit left the pointer at OLD while
        // disk moved to NEW. Reconcile must re-sync so later CASes don't all lose.
        let fake = PointerFake::new(Some("OLD"));
        let out = fake
            .reconcile_pointer("default", "NEW", "filesystem")
            .await
            .unwrap();
        assert_eq!(
            out,
            PointerReconcile::Advanced {
                from: "OLD".to_owned()
            }
        );
        assert_eq!(fake.current().as_deref(), Some("NEW"));
    }

    #[tokio::test]
    async fn reconcile_loses_to_a_concurrent_advance_without_clobbering() {
        // Another replica reconciled/advanced between our read and our CAS. We
        // must NOT force-overwrite — losing is the correct, benign outcome.
        let fake = PointerFake {
            pointer: std::sync::Mutex::new(Some("OLD".to_owned())),
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
            cas_always_loses: true,
        };
        let out = fake
            .reconcile_pointer("default", "NEW", "filesystem")
            .await
            .unwrap();
        assert_eq!(out, PointerReconcile::RacedAnotherReplica);
        assert_eq!(
            fake.current().as_deref(),
            Some("OLD"),
            "a lost reconcile must leave the pointer as the concurrent writer set it",
        );
    }

    #[tokio::test]
    async fn reconcile_defers_a_recently_advanced_pointer_in_flight() {
        // In-flight-writer case: a writer CASed the pointer to NEW moments ago and
        // is still mirroring, so the pointer is legitimately AHEAD of disk (disk
        // still OLD). Reconcile must NOT roll it back — it defers because the
        // pointer was updated within the grace window. (Disk is OLD here, i.e.
        // != the pointer's NEW, exactly as in the mid-mirror window.)
        let fake = PointerFake {
            pointer: std::sync::Mutex::new(Some("NEW".to_owned())),
            updated_at: time::OffsetDateTime::now_utc(),
            cas_always_loses: false,
        };
        let out = fake
            .reconcile_pointer("default", "OLD", "filesystem")
            .await
            .unwrap();
        assert_eq!(out, PointerReconcile::DeferredInFlight);
        assert_eq!(
            fake.current().as_deref(),
            Some("NEW"),
            "a deferred reconcile must not touch the in-flight writer's pointer",
        );
    }

    /// Stateful in-memory fake modeling the bundle ledger, to exercise the
    /// provided `record_filesystem_snapshot` (which composes list_bundles +
    /// create_draft + publish). Single-threaded test use, so the version
    /// assignment is trivially race-free.
    #[derive(Default)]
    struct SnapshotFake {
        bundles: std::sync::Mutex<Vec<ManifestBundle>>,
    }

    #[async_trait]
    impl ManifestStore for SnapshotFake {
        async fn list_bundles(
            &self,
            _t: &str,
        ) -> Result<Vec<ManifestBundleSummary>, ManifestError> {
            Ok(self
                .bundles
                .lock()
                .unwrap()
                .iter()
                .map(|b| ManifestBundleSummary {
                    id: b.id,
                    tenant_id: b.tenant_id.clone(),
                    version: b.version,
                    status: b.status,
                    content_hash: b.content_hash.clone(),
                    author: b.author.clone(),
                    created_at: b.created_at,
                    published_at: b.published_at,
                    published_by: b.published_by.clone(),
                })
                .collect())
        }
        async fn create_draft(
            &self,
            tenant_id: &str,
            content: &str,
            author: Option<&str>,
        ) -> Result<ManifestBundle, ManifestError> {
            let mut g = self.bundles.lock().unwrap();
            let version = g.iter().map(|b| b.version).max().unwrap_or(0) + 1;
            let b = ManifestBundle {
                id: Uuid::now_v7(),
                tenant_id: tenant_id.to_owned(),
                version,
                status: ManifestStatus::Draft,
                content: content.to_owned(),
                content_hash: content_hash(content),
                author: author.map(str::to_owned),
                created_at: time::OffsetDateTime::UNIX_EPOCH,
                published_at: None,
                published_by: None,
            };
            g.push(b.clone());
            Ok(b)
        }
        async fn publish(
            &self,
            _t: &str,
            bundle_id: Uuid,
            publisher: &str,
        ) -> Result<ManifestBundle, ManifestError> {
            let mut g = self.bundles.lock().unwrap();
            let b = g
                .iter_mut()
                .find(|b| b.id == bundle_id && b.status == ManifestStatus::Draft)
                .ok_or(ManifestError::NotFound("no draft with that id"))?;
            b.status = ManifestStatus::Published;
            b.published_at = Some(time::OffsetDateTime::UNIX_EPOCH);
            b.published_by = Some(publisher.to_owned());
            Ok(b.clone())
        }
        async fn active_bundle(&self, _t: &str) -> Result<ManifestBundle, ManifestError> {
            // Newest published bundle (matches the Pg ORDER BY published_at/version).
            self.bundles
                .lock()
                .unwrap()
                .iter()
                .filter(|b| b.status != ManifestStatus::Draft)
                .max_by_key(|b| b.version)
                .cloned()
                .ok_or(ManifestError::NotFound("no published bundle"))
        }
        async fn get(&self, _t: &str, _id: Uuid) -> Result<ManifestBundle, ManifestError> {
            unimplemented!("not used by record_filesystem_snapshot")
        }
        async fn rollback_to(
            &self,
            _t: &str,
            _v: i32,
            _a: &str,
        ) -> Result<ManifestBundle, ManifestError> {
            unimplemented!("not used by record_filesystem_snapshot")
        }
        async fn delete_all_for_tenant(&self, _t: &str) -> Result<u64, ManifestError> {
            unimplemented!("not used by record_filesystem_snapshot")
        }
        async fn read_pointer(&self, _t: &str) -> Result<Option<ManifestPointer>, ManifestError> {
            unimplemented!("not used by record_filesystem_snapshot")
        }
        async fn seed_pointer(&self, _t: &str, _h: &str) -> Result<(), ManifestError> {
            unimplemented!("not used by record_filesystem_snapshot")
        }
        async fn cas_pointer(
            &self,
            _t: &str,
            _e: &str,
            _n: &str,
            _a: &str,
        ) -> Result<TurnstileOutcome, ManifestError> {
            unimplemented!("not used by record_filesystem_snapshot")
        }
    }

    #[tokio::test]
    async fn records_an_out_of_band_snapshot_attributed_to_filesystem() {
        let fake = SnapshotFake::default();
        let out = fake
            .record_filesystem_snapshot("default", "- name: a\n")
            .await
            .unwrap()
            .expect("a new snapshot row");
        assert_eq!(out.status, ManifestStatus::Published);
        assert_eq!(out.author.as_deref(), Some(FILESYSTEM_ACTOR));
        assert_eq!(out.published_by.as_deref(), Some(FILESYSTEM_ACTOR));
        assert_eq!(out.content, "- name: a\n");
        assert_eq!(fake.bundles.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn record_filesystem_snapshot_is_idempotent_on_content_hash() {
        let fake = SnapshotFake::default();
        let first = fake
            .record_filesystem_snapshot("default", "- name: a\n")
            .await
            .unwrap();
        assert!(first.is_some(), "first call records the snapshot");
        // Same content again: a non-draft row already has this hash ⇒ no-op.
        let second = fake
            .record_filesystem_snapshot("default", "- name: a\n")
            .await
            .unwrap();
        assert!(
            second.is_none(),
            "a re-record of the same set must be a no-op (it is now the active)"
        );
        assert_eq!(
            fake.bundles.lock().unwrap().len(),
            1,
            "idempotent against the active snapshot: no duplicate row",
        );
    }

    #[tokio::test]
    async fn record_filesystem_snapshot_records_a_revert_to_an_older_version() {
        // Revert-to-older-version case: history has v1=A and v2=B (active=B). An
        // out-of-band disk REVERT to A must record a NEW filesystem row so the
        // active converges to A — NOT skip just because A still exists as the
        // older v1. The old "any non-draft has this hash" guard wrongly skipped
        // here and the gateway never converged.
        let fake = SnapshotFake::default();
        let a = "- name: a\n";
        let b = "- name: b\n";
        let d1 = fake.create_draft("default", a, None).await.unwrap();
        fake.publish("default", d1.id, "alice").await.unwrap();
        let d2 = fake.create_draft("default", b, None).await.unwrap();
        fake.publish("default", d2.id, "alice").await.unwrap();

        let out = fake.record_filesystem_snapshot("default", a).await.unwrap();
        let bundle = out.expect("a revert to an older version's content must record a NEW row");
        assert_eq!(bundle.content, a);
        assert_eq!(bundle.version, 3, "recorded as the new latest version");
        assert_eq!(bundle.published_by.as_deref(), Some(FILESYSTEM_ACTOR));
        assert_eq!(fake.bundles.lock().unwrap().len(), 3);

        // And it now converges: a second record of A is a no-op (A is active).
        let again = fake.record_filesystem_snapshot("default", a).await.unwrap();
        assert!(
            again.is_none(),
            "now that A is active, re-record is a no-op"
        );
    }
}
