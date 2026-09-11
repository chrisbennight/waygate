//! `PolicyStore` trait + Postgres impl.
//!
//! For the default tenant this trait is the durable HISTORY / RECOVERY ledger
//! beside the file-backed `policies/*.cedar` source of truth. For non-default
//! tenants it is also the live policy source: the gateway loads the latest
//! published bundle for each tenant into an in-memory Cedar registry at boot
//! and on the policy doorbell/poll path. The trait covers read + draft +
//! publish and `rollback_to`; `run_tests` (which needs the Cedar evaluator the
//! gate owns) lives on the admin side rather than this dependency-light crate.

use std::sync::Arc;

use async_trait::async_trait;
use sqlx::postgres::PgPool;
use sqlx::Row;
use uuid::Uuid;

use crate::types::{
    content_hash, ActivePolicyBundleSignature, PointerReconcile, PolicyBundle, PolicyBundlePage,
    PolicyBundleSummary, PolicyError, PolicyHistoryFilter, PolicyPointer, PolicyStatus,
    TurnstileOutcome,
};

/// How long after a turnstile pointer was last advanced [`PolicyStore::reconcile_pointer`]
/// treats it as possibly-mid-flight and DEFERS rather than rolling it back to disk.
/// A writer CASes the pointer BEFORE mirroring the bundle, so the pointer is
/// legitimately *ahead* of disk for the duration of that mirror; this window must
/// comfortably exceed a mirror (a few atomic renames — sub-second even on NFS)
/// plus gateway↔DB clock skew. Mirrors `waygate_manifest_store::RECONCILE_GRACE`.
pub const RECONCILE_GRACE: time::Duration = time::Duration::seconds(15);

/// The Postgres channel the policy doorbell uses. `NOTIFY`/`LISTEN`
/// channel identifiers can't be bound parameters, so it is a single shared
/// constant rather than interpolated per call. Distinct from the manifest
/// channel (`mcp_manifest_reload`) so a policy write only wakes the policy
/// reload, not a manifest re-dial. Mirrors `MANIFEST_RELOAD_CHANNEL`.
pub const POLICY_RELOAD_CHANNEL: &str = "mcp_policy_reload";

/// Decoupled store surface so callers (the `ReloadableCedar` loader,
/// admin endpoints) don't reach for the Postgres pool directly. Tests
/// implement an in-memory variant; production wires [`PgPolicyStore`].
#[async_trait]
pub trait PolicyStore: Send + Sync + 'static {
    /// The tenant's active policy bundle: the **most recently
    /// published** one (`ORDER BY published_at DESC`, `version DESC`
    /// only as a same-instant tiebreak) — not the highest version
    /// number. "Publish makes it live", so re-publishing an older
    /// version's content (a rollback) takes effect immediately. Hot
    /// path — the gate consults it on reload, not per call. `NotFound`
    /// when the tenant has no published bundle (a fresh tenant before
    /// its policies are imported/published).
    async fn active_bundle(&self, tenant_id: &str) -> Result<PolicyBundle, PolicyError>;

    /// Latest published bundle for every tenant that has one. Runtime policy
    /// reload uses this as one snapshot so it can compile a complete tenant
    /// registry before atomically replacing the live set.
    async fn active_bundles(&self) -> Result<Vec<PolicyBundle>, PolicyError>;

    /// Tenant and content hash for every active bundle. Polling uses this
    /// lightweight projection to avoid fetching and compiling unchanged Cedar
    /// source. The default keeps test and alternate stores source-compatible;
    /// production stores should override it with a metadata-only read.
    async fn active_bundle_signatures(
        &self,
    ) -> Result<Vec<ActivePolicyBundleSignature>, PolicyError> {
        Ok(self
            .active_bundles()
            .await?
            .into_iter()
            .map(|bundle| ActivePolicyBundleSignature {
                tenant_id: bundle.tenant_id,
                content_hash: bundle.content_hash,
            })
            .collect())
    }

    /// Every bundle for the tenant, newest version first, without the
    /// Cedar source (use [`Self::active_bundle`] or [`Self::get`] when
    /// the source is needed).
    async fn list_bundles(&self, tenant_id: &str) -> Result<Vec<PolicyBundleSummary>, PolicyError>;

    /// A bounded page of draft or previously-published history. Production
    /// stores must apply the filter, limit, and offset in the database. The
    /// default keeps existing test fakes source-compatible.
    async fn list_bundles_page(
        &self,
        tenant_id: &str,
        filter: PolicyHistoryFilter,
        limit: u32,
        offset: u32,
    ) -> Result<PolicyBundlePage, PolicyError> {
        let bundles: Vec<_> = self
            .list_bundles(tenant_id)
            .await?
            .into_iter()
            .filter(|bundle| filter.matches(bundle.status))
            .collect();
        let total = u64::try_from(bundles.len()).unwrap_or(u64::MAX);
        let offset = usize::try_from(offset).unwrap_or(usize::MAX);
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        Ok(PolicyBundlePage {
            total,
            bundles: bundles.into_iter().skip(offset).take(limit).collect(),
        })
    }

    /// A single bundle by id, scoped to the caller's tenant. Returns the
    /// full `PolicyBundle` (including `content`) so the editor can
    /// pre-fill a textarea from any version — draft, published, or
    /// rolled_back — not just the active one. Tenant predicate enforces
    /// ownership at the read boundary so a bookmarked `?load=<id>` URL
    /// from one tenant can't surface another tenant's policy source.
    /// Returns `NotFound` for an absent id or a different-tenant id.
    async fn get(&self, tenant_id: &str, bundle_id: Uuid) -> Result<PolicyBundle, PolicyError>;

    /// A single previously-published bundle by tenant-local version.
    async fn get_by_version(
        &self,
        _tenant_id: &str,
        _version: i32,
    ) -> Result<PolicyBundle, PolicyError> {
        Err(PolicyError::NotFound(
            "get_by_version not supported by this store",
        ))
    }

    /// Append a new `draft` bundle at the next version for the tenant.
    /// The version is assigned atomically (`MAX(version)+1` in the
    /// INSERT); a concurrent `create_draft` that races to the same
    /// version hits the `UNIQUE (tenant_id, version)` constraint and
    /// surfaces as a `Database` error the caller can retry.
    ///
    /// `tests` is the optional policy-test JSON written to the reserved
    /// `tests JSONB` column (migration 0012). The store is content-agnostic
    /// about its shape (the typed cases live in `waygate-admin`); it round-
    /// trips the column so a later publish gate can deserialize and run them.
    /// Written in the same INSERT as the content so the tests never lag the
    /// draft they gate. `None` stages a draft with no attached tests.
    async fn create_draft(
        &self,
        tenant_id: &str,
        content: &str,
        tests: Option<&serde_json::Value>,
        author: Option<&str>,
    ) -> Result<PolicyBundle, PolicyError>;

    /// Promote a `draft` bundle to `published`, stamping
    /// `published_at` / `published_by`. Conditional on the row still
    /// being a draft, so two concurrent publishes don't double-stamp:
    /// the second sees no `draft` row and gets `NotFound`. Publishing
    /// doesn't demote prior published versions — the active bundle is
    /// simply the newest published one, which keeps the full version
    /// history intact for rollback.
    ///
    /// Scoped to `tenant_id`: the UPDATE only matches a draft the
    /// caller's tenant owns, mirroring the tenant predicate on the
    /// other methods (and `CatalogStore::set_server_status`). This
    /// enforces ownership at the write boundary so a future
    /// tenant-scoped admin API can't publish another tenant's draft by
    /// guessing its bundle id.
    async fn publish(
        &self,
        tenant_id: &str,
        bundle_id: Uuid,
        publisher: &str,
    ) -> Result<PolicyBundle, PolicyError>;

    /// Roll the active policy back to a previously-published `version`'s
    /// content by re-publishing that content as a NEW bundle at the next
    /// version number. Append-only (roll-forward): the old rows are
    /// untouched, and because the active bundle is the most recently
    /// published one, the new copy immediately becomes active.
    ///
    /// The target `(tenant_id, version)` must exist and have been
    /// published at some point (status `published` or `rolled_back`);
    /// rolling back to a never-published draft is rejected with
    /// `NotFound`, so rollback can only re-activate vetted content.
    /// Returns the newly-created active bundle.
    async fn rollback_to(
        &self,
        tenant_id: &str,
        version: i32,
        actor: &str,
    ) -> Result<PolicyBundle, PolicyError>;

    /// Bulk-delete every bundle (drafts + published) for a
    /// tenant. Called from the tenant
    /// DELETE path so a re-created tenant id starts with an empty
    /// bundle history (otherwise the next onboarding's "clone
    /// default as v1" would land at v2 because v1+ already exist,
    /// and the report's `policy_bundle: seeded` would be
    /// misleading). Returns the number of bundle rows deleted so
    /// the handler can audit + log it.
    async fn delete_all_bundles_for_tenant(&self, tenant_id: &str) -> Result<u64, PolicyError>;

    // --- Cross-replica write turnstile ------------------------------------

    /// Read the turnstile pointer for the tenant: the canonical hash of the
    /// current live on-disk policy set. `None` when it has not been seeded yet
    /// (a fresh deploy before the first boot seed / write). Mirrors
    /// `ManifestStore::read_pointer`.
    async fn read_pointer(&self, tenant_id: &str) -> Result<Option<PolicyPointer>, PolicyError>;

    /// Seed the turnstile pointer at `hash` IF absent (`ON CONFLICT DO
    /// NOTHING`). Idempotent and never clobbers a pointer another replica may
    /// have advanced — boot calls it to establish the pointer at the current
    /// live disk hash without racing a concurrent writer.
    async fn seed_pointer(&self, tenant_id: &str, hash: &str) -> Result<(), PolicyError>;

    /// Compare-and-swap the turnstile pointer from `expected_hash` to
    /// `new_hash`. Atomic conditional UPDATE: `Won` when this writer advanced it
    /// (rows_affected == 1), `Lost` when the live hash no longer matched
    /// `expected_hash` (another replica advanced it first, or the pointer is
    /// absent). Callers run this BEFORE mirroring the bundle to disk, so only
    /// the winner ever renames — the clobber is prevented, not just detected.
    async fn cas_pointer(
        &self,
        tenant_id: &str,
        expected_hash: &str,
        new_hash: &str,
        actor: &str,
    ) -> Result<TurnstileOutcome, PolicyError>;

    /// Reconcile the turnstile pointer to the actual on-disk hash. An
    /// out-of-band edit to `policies/*.cedar` — or a boot/restart that loads a
    /// disk set the persisted pointer never saw — otherwise leaves the pointer
    /// stale, so every later `cas_pointer` from the current disk hash loses and
    /// dashboard/API policy writes permanently fail. Callers run this on boot
    /// (clean disk load), SIGHUP/doorbell reload, and dashboard Reload so the
    /// pointer tracks disk.
    ///
    /// ## Why it must not blindly CAS the pointer to disk
    ///
    /// The write paths deliberately advance the pointer BEFORE mirroring the file
    /// (`cas_pointer(disk -> new)` then mirror), so for the duration of a writer's
    /// mirror the pointer is legitimately *ahead* of disk — pointer == new, disk
    /// still == old. Treating every `pointer != disk` as stale and CASing the
    /// observed pointer back to the disk hash would roll back a mid-flight writer
    /// and reintroduce the very lost update the turnstile exists to prevent. The
    /// distinguisher is TIME: a mid-flight writer converges disk to the pointer
    /// within its mirror (sub-second), whereas a true out-of-band divergence
    /// persists. So we only reconcile a pointer whose `updated_at` is older than
    /// [`RECONCILE_GRACE`]; a more-recently-advanced pointer is DEFERRED and
    /// re-checked on the next reload. Still race-safe in the act-now branch: the
    /// CAS is conditional on the value we read, so a writer's advance landing
    /// between the read and the CAS just makes this lose (`RacedAnotherReplica`).
    ///
    /// Provided method composing [`Self::read_pointer`], [`Self::seed_pointer`],
    /// and [`Self::cas_pointer`], so every store (Postgres + the test fakes)
    /// inherits it and it is covered by the trait-level unit tests. Mirrors
    /// `waygate_manifest_store::ManifestStore::reconcile_pointer`.
    async fn reconcile_pointer(
        &self,
        tenant_id: &str,
        disk_hash: &str,
        actor: &str,
    ) -> Result<PointerReconcile, PolicyError> {
        match self.read_pointer(tenant_id).await? {
            None => {
                self.seed_pointer(tenant_id, disk_hash).await?;
                Ok(PointerReconcile::Seeded)
            }
            Some(p) if p.current_hash == disk_hash => Ok(PointerReconcile::AlreadyInSync),
            Some(p) => {
                // Defer if the pointer was advanced within the grace window — a
                // writer may have CASed it and not yet finished its mirror, so it
                // is legitimately ahead of disk, not stale.
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

    /// Record the current on-disk policy set as a `published` ledger bundle
    /// attributed to [`FILESYSTEM_ACTOR`]. Boot/reload call this when
    /// the on-disk `policies/*.cedar` set has drifted from the latest published
    /// bundle — an out-of-band git edit that bypassed the dashboard, OR the
    /// disk-wins residue of a ledger failure or `published_at` race.
    /// Capturing it converges the ledger to disk (disk is the source of truth):
    /// the out-of-band state becomes visible in history and is rollback-able.
    ///
    /// `content` is the caller's canonical on-disk content (the source that, when
    /// mirrored, reproduces disk — see `waygate-server`'s capture path), so
    /// `content_hash(content)` is the row's hash. The store is content-agnostic;
    /// the caller owns the "is this drift?" comparison (it needs the Cedar
    /// canonicalization the store can't do).
    ///
    /// Idempotent against the **ACTIVE** snapshot only: `Ok(None)` if the latest
    /// published bundle already has this content hash. A match on an *older*
    /// version must NOT skip — a disk revert to an earlier version's content has
    /// to become the new latest snapshot or the gateway never converges and every
    /// reload re-detects the same drift. Else
    /// `Ok(Some(bundle))` for the new row. Provided method composing
    /// [`Self::active_bundle`] / [`Self::create_draft`] / [`Self::publish`], so
    /// every store inherits it; mirrors `ManifestStore::record_filesystem_snapshot`.
    async fn record_filesystem_snapshot(
        &self,
        tenant_id: &str,
        content: &str,
    ) -> Result<Option<PolicyBundle>, PolicyError> {
        let hash = content_hash(content);
        match self.active_bundle(tenant_id).await {
            Ok(active) if active.content_hash == hash => return Ok(None),
            Ok(_) => {}
            Err(PolicyError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
        let draft = self
            .create_draft(tenant_id, content, None, Some(FILESYSTEM_ACTOR))
            .await?;
        let published = self.publish(tenant_id, draft.id, FILESYSTEM_ACTOR).await?;
        Ok(Some(published))
    }

    /// Doorbell: fire a Postgres `NOTIFY` on the
    /// [`POLICY_RELOAD_CHANNEL`] after a successful policy publish/rollback
    /// (write + ledger append), carrying a change fingerprint as the payload.
    /// For the default tenant this is the new canonical on-disk hash; for a
    /// ledger-backed tenant it is the bundle hash (or a deletion fingerprint).
    /// Every gateway replica `LISTEN`s on that channel and refreshes both the
    /// shared default `policies/*.cedar` set and the tenant registry, so an edit
    /// on one replica propagates without waiting for the poll backstop.
    /// Best-effort at the call site: a notify failure is logged, never fails the
    /// edit — the poll still converges. Mirrors `ManifestStore::notify_reload`.
    ///
    /// Default no-op: a non-Postgres store (the test fakes, a future file-only
    /// store) has no doorbell, so it inherits this and the poll backstop is the
    /// only propagation path. [`PgPolicyStore`] overrides it with a real
    /// `pg_notify`.
    async fn notify_reload(&self, _hash: &str) -> Result<(), PolicyError> {
        Ok(())
    }
}

/// Author / `published_by` attribution for a ledger bundle the gateway itself
/// synthesized from an out-of-band on-disk policy edit (or disk-wins residue),
/// distinct from any human principal. Surfaced in dashboard history so
/// an operator can tell a `filesystem` convergence row from a real publish.
/// Mirrors `waygate_manifest_store::FILESYSTEM_ACTOR`.
pub const FILESYSTEM_ACTOR: &str = "filesystem";

/// Type-erased handle, matching the shape every other store in this
/// workspace uses (`SharedCatalogStore`, `SharedEvidence`).
pub type SharedPolicyStore = Arc<dyn PolicyStore>;

/// Postgres-backed [`PolicyStore`]. One instance per gateway boot;
/// cheaply `Clone`-able because `PgPool` is internally an `Arc`.
#[derive(Clone)]
pub struct PgPolicyStore {
    pool: PgPool,
}

impl PgPolicyStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> PgPool {
        self.pool.clone()
    }
}

/// Columns selected for a full [`PolicyBundle`]. Kept in one place so
/// the active-bundle / create-draft / publish queries stay in sync.
const BUNDLE_COLS: &str = "id, tenant_id, version, status, content, content_hash, \
                           tests, author, created_at, published_at, published_by";

#[async_trait]
impl PolicyStore for PgPolicyStore {
    async fn active_bundle(&self, tenant_id: &str) -> Result<PolicyBundle, PolicyError> {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            // `NULLS LAST` is belt-and-suspenders: the 0012 CHECK
            // already guarantees a published row has a non-NULL
            // published_at, but Postgres defaults DESC to NULLS FIRST,
            // so spelling it out keeps the query correct even if the
            // invariant were ever loosened.
            "SELECT {BUNDLE_COLS} \
               FROM policy_bundles \
              WHERE tenant_id = $1 AND status = 'published' \
              ORDER BY published_at DESC NULLS LAST, version DESC \
              LIMIT 1"
        )))
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(PolicyError::Database)?;
        match row {
            Some(r) => bundle_from_row(&r),
            None => Err(PolicyError::NotFound(
                "no published policy bundle for tenant",
            )),
        }
    }

    async fn active_bundles(&self) -> Result<Vec<PolicyBundle>, PolicyError> {
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT DISTINCT ON (tenant_id) {BUNDLE_COLS} \
               FROM policy_bundles \
              WHERE status = 'published' \
                AND (tenant_id = 'default' OR EXISTS ( \
                    SELECT 1 FROM tenants WHERE tenants.id = policy_bundles.tenant_id \
                )) \
              ORDER BY tenant_id, published_at DESC NULLS LAST, version DESC"
        )))
        .fetch_all(&self.pool)
        .await
        .map_err(PolicyError::Database)?;
        rows.iter().map(bundle_from_row).collect()
    }

    async fn active_bundle_signatures(
        &self,
    ) -> Result<Vec<ActivePolicyBundleSignature>, PolicyError> {
        let rows = sqlx::query(
            "SELECT DISTINCT ON (tenant_id) tenant_id, content_hash \
               FROM policy_bundles \
              WHERE status = 'published' \
                AND (tenant_id = 'default' OR EXISTS ( \
                    SELECT 1 FROM tenants WHERE tenants.id = policy_bundles.tenant_id \
                )) \
              ORDER BY tenant_id, published_at DESC NULLS LAST, version DESC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(PolicyError::Database)?;
        rows.iter()
            .map(|row| {
                Ok(ActivePolicyBundleSignature {
                    tenant_id: row.try_get("tenant_id").map_err(PolicyError::Database)?,
                    content_hash: row.try_get("content_hash").map_err(PolicyError::Database)?,
                })
            })
            .collect()
    }

    async fn list_bundles(&self, tenant_id: &str) -> Result<Vec<PolicyBundleSummary>, PolicyError> {
        let rows = sqlx::query(
            "SELECT id, tenant_id, version, status, content_hash, \
                    author, created_at, published_at, published_by \
               FROM policy_bundles \
              WHERE tenant_id = $1 \
              ORDER BY version DESC",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(PolicyError::Database)?;
        rows.iter().map(summary_from_row).collect()
    }

    async fn list_bundles_page(
        &self,
        tenant_id: &str,
        filter: PolicyHistoryFilter,
        limit: u32,
        offset: u32,
    ) -> Result<PolicyBundlePage, PolicyError> {
        let drafts = filter == PolicyHistoryFilter::Draft;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) \
               FROM policy_bundles \
              WHERE tenant_id = $1 \
                AND (($2 AND status = 'draft') OR (NOT $2 AND status <> 'draft'))",
        )
        .bind(tenant_id)
        .bind(drafts)
        .fetch_one(&self.pool)
        .await
        .map_err(PolicyError::Database)?;
        let rows = sqlx::query(
            "SELECT id, tenant_id, version, status, content_hash, \
                    author, created_at, published_at, published_by \
               FROM policy_bundles \
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
        .map_err(PolicyError::Database)?;
        Ok(PolicyBundlePage {
            total: u64::try_from(total).expect("COUNT(*) is nonnegative"),
            bundles: rows
                .iter()
                .map(summary_from_row)
                .collect::<Result<_, _>>()?,
        })
    }

    async fn get(&self, tenant_id: &str, bundle_id: Uuid) -> Result<PolicyBundle, PolicyError> {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {BUNDLE_COLS} \
               FROM policy_bundles \
              WHERE id = $1 AND tenant_id = $2 \
              LIMIT 1"
        )))
        .bind(bundle_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(PolicyError::Database)?;
        match row {
            Some(r) => bundle_from_row(&r),
            None => Err(PolicyError::NotFound(
                "no policy bundle with that id in tenant",
            )),
        }
    }

    async fn get_by_version(
        &self,
        tenant_id: &str,
        version: i32,
    ) -> Result<PolicyBundle, PolicyError> {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {BUNDLE_COLS} \
               FROM policy_bundles \
              WHERE tenant_id = $1 AND version = $2 AND status <> 'draft' \
              LIMIT 1"
        )))
        .bind(tenant_id)
        .bind(version)
        .fetch_optional(&self.pool)
        .await
        .map_err(PolicyError::Database)?;
        match row {
            Some(row) => bundle_from_row(&row),
            None => Err(PolicyError::NotFound(
                "no previously-published policy bundle at that version",
            )),
        }
    }

    async fn create_draft(
        &self,
        tenant_id: &str,
        content: &str,
        tests: Option<&serde_json::Value>,
        author: Option<&str>,
    ) -> Result<PolicyBundle, PolicyError> {
        let hash = content_hash(content);
        // Version assigned in-statement so there's no read-then-write
        // gap; the UNIQUE constraint is the backstop if two drafts race
        // to the same MAX+1. The tests JSON lands in the SAME INSERT as
        // the content, so the gate-eligible tests can never lag the draft.
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO policy_bundles \
                 (id, tenant_id, version, status, content, content_hash, tests, author) \
             VALUES ($1, $2, \
                     (SELECT COALESCE(MAX(version), 0) + 1 \
                        FROM policy_bundles WHERE tenant_id = $2), \
                     'draft', $3, $4, $5, $6) \
             RETURNING {BUNDLE_COLS}"
        )))
        .bind(Uuid::now_v7())
        .bind(tenant_id)
        .bind(content)
        .bind(&hash)
        .bind(tests)
        .bind(author)
        .fetch_one(&self.pool)
        .await
        .map_err(PolicyError::Database)?;
        bundle_from_row(&row)
    }

    async fn publish(
        &self,
        tenant_id: &str,
        bundle_id: Uuid,
        publisher: &str,
    ) -> Result<PolicyBundle, PolicyError> {
        // Conditional UPDATE: only a row that is still `draft` AND owned
        // by this tenant transitions. A no-op (already published,
        // rolled back, absent, or another tenant's) returns no row →
        // NotFound. The tenant predicate enforces ownership at the
        // write boundary.
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "UPDATE policy_bundles \
                SET status = 'published', published_at = now(), published_by = $3 \
              WHERE id = $1 AND tenant_id = $2 AND status = 'draft' \
            RETURNING {BUNDLE_COLS}"
        )))
        .bind(bundle_id)
        .bind(tenant_id)
        .bind(publisher)
        .fetch_optional(&self.pool)
        .await
        .map_err(PolicyError::Database)?;
        match row {
            Some(r) => bundle_from_row(&r),
            None => Err(PolicyError::NotFound(
                "no draft policy bundle with that id in tenant",
            )),
        }
    }

    async fn rollback_to(
        &self,
        tenant_id: &str,
        version: i32,
        actor: &str,
    ) -> Result<PolicyBundle, PolicyError> {
        // Single INSERT...SELECT: copy the target version's (immutable)
        // content into a new published bundle at MAX+1, in one statement
        // so there's no read-then-write gap. The SELECT's WHERE requires
        // the target to exist AND to have been published (status <>
        // 'draft'); if it matches nothing, zero rows insert and
        // RETURNING is empty → NotFound. The UNIQUE(tenant_id, version)
        // constraint backstops a concurrent version collision.
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO policy_bundles \
                 (id, tenant_id, version, status, content, content_hash, \
                  tests, author, published_at, published_by) \
             SELECT $1, tenant_id, \
                    (SELECT COALESCE(MAX(version), 0) + 1 \
                       FROM policy_bundles WHERE tenant_id = $2), \
                    'published', content, content_hash, tests, $4, now(), $4 \
               FROM policy_bundles \
              WHERE tenant_id = $2 AND version = $3 AND status <> 'draft' \
            RETURNING {BUNDLE_COLS}"
        )))
        .bind(Uuid::now_v7())
        .bind(tenant_id)
        .bind(version)
        .bind(actor)
        .fetch_optional(&self.pool)
        .await
        .map_err(PolicyError::Database)?;
        match row {
            Some(r) => bundle_from_row(&r),
            None => Err(PolicyError::NotFound(
                "no published policy bundle at that version in tenant",
            )),
        }
    }

    async fn delete_all_bundles_for_tenant(&self, tenant_id: &str) -> Result<u64, PolicyError> {
        let result = sqlx::query("DELETE FROM policy_bundles WHERE tenant_id = $1")
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(PolicyError::Database)?;
        Ok(result.rows_affected())
    }

    async fn read_pointer(&self, tenant_id: &str) -> Result<Option<PolicyPointer>, PolicyError> {
        let row = sqlx::query(
            "SELECT tenant_id, current_hash, updated_at, updated_by \
               FROM policy_pointer WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(PolicyError::Database)?;
        Ok(row.map(|r| PolicyPointer {
            tenant_id: r.get("tenant_id"),
            current_hash: r.get("current_hash"),
            updated_at: r.get("updated_at"),
            updated_by: r.get("updated_by"),
        }))
    }

    async fn seed_pointer(&self, tenant_id: &str, hash: &str) -> Result<(), PolicyError> {
        // ON CONFLICT DO NOTHING: idempotent seed. Establishes the pointer at
        // the current live disk hash on first boot; a no-op if another replica
        // already seeded or advanced it, so it never clobbers a concurrent
        // writer's value.
        sqlx::query(
            "INSERT INTO policy_pointer (tenant_id, current_hash) \
             VALUES ($1, $2) ON CONFLICT (tenant_id) DO NOTHING",
        )
        .bind(tenant_id)
        .bind(hash)
        .execute(&self.pool)
        .await
        .map_err(PolicyError::Database)?;
        Ok(())
    }

    async fn cas_pointer(
        &self,
        tenant_id: &str,
        expected_hash: &str,
        new_hash: &str,
        actor: &str,
    ) -> Result<TurnstileOutcome, PolicyError> {
        // Atomic conditional UPDATE. tenant_id is the PK, so at most one row
        // matches: rows_affected is 1 (won) or 0 (the live hash moved off
        // `expected_hash`, or the pointer isn't seeded). No transaction needed —
        // a single statement is the serialization point.
        let result = sqlx::query(
            "UPDATE policy_pointer \
                SET current_hash = $3, updated_at = now(), updated_by = $4 \
              WHERE tenant_id = $1 AND current_hash = $2",
        )
        .bind(tenant_id)
        .bind(expected_hash)
        .bind(new_hash)
        .bind(actor)
        .execute(&self.pool)
        .await
        .map_err(PolicyError::Database)?;
        Ok(if result.rows_affected() == 1 {
            TurnstileOutcome::Won
        } else {
            TurnstileOutcome::Lost
        })
    }

    async fn notify_reload(&self, hash: &str) -> Result<(), PolicyError> {
        // pg_notify(channel, payload): the channel can't be a bound param, so
        // it is the compile-time constant; the payload (hash) is bound.
        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(POLICY_RELOAD_CHANNEL)
            .bind(hash)
            .execute(&self.pool)
            .await
            .map_err(PolicyError::Database)?;
        Ok(())
    }
}

fn parse_status(s: &str) -> Result<PolicyStatus, PolicyError> {
    Ok(match s {
        "draft" => PolicyStatus::Draft,
        "published" => PolicyStatus::Published,
        "rolled_back" => PolicyStatus::RolledBack,
        other => return Err(PolicyError::UnknownStatus(other.to_owned())),
    })
}

fn bundle_from_row(r: &sqlx::postgres::PgRow) -> Result<PolicyBundle, PolicyError> {
    Ok(PolicyBundle {
        id: r.get("id"),
        tenant_id: r.get("tenant_id"),
        version: r.get("version"),
        status: parse_status(r.get::<&str, _>("status"))?,
        content: r.get("content"),
        content_hash: r.get("content_hash"),
        // JSONB column → Option<serde_json::Value>; NULL maps to None.
        tests: r.get("tests"),
        author: r.get("author"),
        created_at: r.get("created_at"),
        published_at: r.get("published_at"),
        published_by: r.get("published_by"),
    })
}

fn summary_from_row(r: &sqlx::postgres::PgRow) -> Result<PolicyBundleSummary, PolicyError> {
    Ok(PolicyBundleSummary {
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
    fn policy_reload_channel_is_distinct_from_the_manifest_channel() {
        // The policy doorbell must use its own channel so a policy write
        // wakes only the Cedar reload, never a manifest re-dial. Pin the literal
        // and its distinctness from the manifest channel name (the pg_doorbell
        // isolation smoke listens on this same manifest literal).
        assert_eq!(POLICY_RELOAD_CHANNEL, "mcp_policy_reload");
        assert_ne!(POLICY_RELOAD_CHANNEL, "mcp_manifest_reload");
    }

    #[test]
    fn parse_status_accepts_check_vocabulary() {
        assert_eq!(parse_status("draft").unwrap(), PolicyStatus::Draft);
        assert_eq!(parse_status("published").unwrap(), PolicyStatus::Published);
        assert_eq!(
            parse_status("rolled_back").unwrap(),
            PolicyStatus::RolledBack
        );
    }

    #[test]
    fn parse_status_rejects_unknown() {
        // A status outside the migration's CHECK vocabulary is a typed
        // error, not a panic — a running gateway tolerates a future
        // migration adding a value until it picks up matching code.
        match parse_status("archived") {
            Err(PolicyError::UnknownStatus(s)) => assert_eq!(s, "archived"),
            other => panic!("expected UnknownStatus, got {other:?}"),
        }
    }

    /// Stateful in-memory fake modeling ONLY the turnstile pointer, to exercise
    /// the provided `reconcile_pointer` logic without a database. Every other
    /// `PolicyStore` method is `unimplemented!()` — `reconcile_pointer` calls only
    /// read/seed/cas. `updated_at` is what `read_pointer` reports (drives the
    /// grace check); `cas_always_loses` simulates a concurrent advance between the
    /// read and the CAS (the `RacedAnotherReplica` path). Mirrors the manifest
    /// store's `PointerFake`.
    struct PointerFake {
        pointer: std::sync::Mutex<Option<String>>,
        updated_at: time::OffsetDateTime,
        cas_always_loses: bool,
    }

    impl PointerFake {
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
    impl PolicyStore for PointerFake {
        async fn read_pointer(
            &self,
            _tenant_id: &str,
        ) -> Result<Option<PolicyPointer>, PolicyError> {
            Ok(self.current().map(|h| PolicyPointer {
                tenant_id: "default".into(),
                current_hash: h,
                updated_at: self.updated_at,
                updated_by: None,
            }))
        }
        async fn seed_pointer(&self, _tenant_id: &str, hash: &str) -> Result<(), PolicyError> {
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
        ) -> Result<TurnstileOutcome, PolicyError> {
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
        async fn active_bundle(&self, _t: &str) -> Result<PolicyBundle, PolicyError> {
            unimplemented!("not used by reconcile_pointer")
        }
        async fn active_bundles(&self) -> Result<Vec<PolicyBundle>, PolicyError> {
            unimplemented!("not used by reconcile_pointer")
        }
        async fn list_bundles(&self, _t: &str) -> Result<Vec<PolicyBundleSummary>, PolicyError> {
            unimplemented!("not used by reconcile_pointer")
        }
        async fn get(&self, _t: &str, _id: Uuid) -> Result<PolicyBundle, PolicyError> {
            unimplemented!("not used by reconcile_pointer")
        }
        async fn create_draft(
            &self,
            _t: &str,
            _content: &str,
            _tests: Option<&serde_json::Value>,
            _author: Option<&str>,
        ) -> Result<PolicyBundle, PolicyError> {
            unimplemented!("not used by reconcile_pointer")
        }
        async fn publish(
            &self,
            _t: &str,
            _id: Uuid,
            _publisher: &str,
        ) -> Result<PolicyBundle, PolicyError> {
            unimplemented!("not used by reconcile_pointer")
        }
        async fn rollback_to(
            &self,
            _t: &str,
            _version: i32,
            _actor: &str,
        ) -> Result<PolicyBundle, PolicyError> {
            unimplemented!("not used by reconcile_pointer")
        }
        async fn delete_all_bundles_for_tenant(&self, _t: &str) -> Result<u64, PolicyError> {
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
        // An out-of-band edit left the pointer at OLD while
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
        // A writer CASed the pointer to NEW moments ago and is
        // still mirroring, so the pointer is legitimately AHEAD of disk (disk still
        // OLD). Reconcile must NOT roll it back — it defers because the pointer was
        // updated within the grace window.
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
    /// provided `record_filesystem_snapshot` (active_bundle + create_draft +
    /// publish). Single-threaded test use, so the version assignment is race-free.
    #[derive(Default)]
    struct LedgerFake {
        bundles: std::sync::Mutex<Vec<PolicyBundle>>,
    }

    #[async_trait]
    impl PolicyStore for LedgerFake {
        async fn create_draft(
            &self,
            tenant_id: &str,
            content: &str,
            tests: Option<&serde_json::Value>,
            author: Option<&str>,
        ) -> Result<PolicyBundle, PolicyError> {
            let mut g = self.bundles.lock().unwrap();
            let version = g.iter().map(|b| b.version).max().unwrap_or(0) + 1;
            let b = PolicyBundle {
                id: Uuid::now_v7(),
                tenant_id: tenant_id.to_owned(),
                version,
                status: PolicyStatus::Draft,
                content: content.to_owned(),
                content_hash: content_hash(content),
                tests: tests.cloned(),
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
        ) -> Result<PolicyBundle, PolicyError> {
            let mut g = self.bundles.lock().unwrap();
            let b = g
                .iter_mut()
                .find(|b| b.id == bundle_id && b.status == PolicyStatus::Draft)
                .ok_or(PolicyError::NotFound("no draft with that id"))?;
            b.status = PolicyStatus::Published;
            b.published_at = Some(time::OffsetDateTime::UNIX_EPOCH);
            b.published_by = Some(publisher.to_owned());
            Ok(b.clone())
        }
        async fn active_bundle(&self, _t: &str) -> Result<PolicyBundle, PolicyError> {
            // Newest published bundle (matches the Pg ORDER BY published_at/version).
            self.bundles
                .lock()
                .unwrap()
                .iter()
                .filter(|b| b.status != PolicyStatus::Draft)
                .max_by_key(|b| b.version)
                .cloned()
                .ok_or(PolicyError::NotFound("no published bundle"))
        }
        async fn active_bundles(&self) -> Result<Vec<PolicyBundle>, PolicyError> {
            match self.active_bundle("default").await {
                Ok(bundle) => Ok(vec![bundle]),
                Err(PolicyError::NotFound(_)) => Ok(Vec::new()),
                Err(error) => Err(error),
            }
        }
        async fn list_bundles(&self, _t: &str) -> Result<Vec<PolicyBundleSummary>, PolicyError> {
            unimplemented!("not used by record_filesystem_snapshot")
        }
        async fn get(&self, _t: &str, _id: Uuid) -> Result<PolicyBundle, PolicyError> {
            unimplemented!("not used by record_filesystem_snapshot")
        }
        async fn rollback_to(
            &self,
            _t: &str,
            _v: i32,
            _a: &str,
        ) -> Result<PolicyBundle, PolicyError> {
            unimplemented!("not used by record_filesystem_snapshot")
        }
        async fn delete_all_bundles_for_tenant(&self, _t: &str) -> Result<u64, PolicyError> {
            unimplemented!("not used by record_filesystem_snapshot")
        }
        async fn read_pointer(&self, _t: &str) -> Result<Option<PolicyPointer>, PolicyError> {
            unimplemented!("not used by record_filesystem_snapshot")
        }
        async fn seed_pointer(&self, _t: &str, _h: &str) -> Result<(), PolicyError> {
            unimplemented!("not used by record_filesystem_snapshot")
        }
        async fn cas_pointer(
            &self,
            _t: &str,
            _e: &str,
            _n: &str,
            _a: &str,
        ) -> Result<TurnstileOutcome, PolicyError> {
            unimplemented!("not used by record_filesystem_snapshot")
        }
    }

    #[tokio::test]
    async fn records_an_out_of_band_snapshot_attributed_to_filesystem() {
        let fake = LedgerFake::default();
        let out = fake
            .record_filesystem_snapshot("default", "permit(principal, action, resource);")
            .await
            .unwrap()
            .expect("a new snapshot row");
        assert_eq!(out.status, PolicyStatus::Published);
        assert_eq!(out.author.as_deref(), Some(FILESYSTEM_ACTOR));
        assert_eq!(out.published_by.as_deref(), Some(FILESYSTEM_ACTOR));
        assert_eq!(out.content, "permit(principal, action, resource);");
        assert_eq!(fake.bundles.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn record_filesystem_snapshot_is_idempotent_on_content_hash() {
        let fake = LedgerFake::default();
        let a = "permit(principal, action, resource);";
        assert!(
            fake.record_filesystem_snapshot("default", a)
                .await
                .unwrap()
                .is_some(),
            "first call records the snapshot",
        );
        assert!(
            fake.record_filesystem_snapshot("default", a)
                .await
                .unwrap()
                .is_none(),
            "a re-record of the same set is a no-op (it is now the active)",
        );
        assert_eq!(
            fake.bundles.lock().unwrap().len(),
            1,
            "idempotent against the active snapshot: no duplicate row",
        );
    }

    #[tokio::test]
    async fn record_filesystem_snapshot_records_a_revert_to_an_older_version() {
        // History has v1=A and v2=B (active=B). An out-of-band disk
        // REVERT to A must record a NEW filesystem row so the active converges to
        // A — NOT skip just because A still exists as the older v1.
        let fake = LedgerFake::default();
        let a = "permit(principal, action, resource);";
        let b = "forbid(principal, action, resource);";
        let d1 = fake.create_draft("default", a, None, None).await.unwrap();
        fake.publish("default", d1.id, "alice").await.unwrap();
        let d2 = fake.create_draft("default", b, None, None).await.unwrap();
        fake.publish("default", d2.id, "alice").await.unwrap();

        let bundle = fake
            .record_filesystem_snapshot("default", a)
            .await
            .unwrap()
            .expect("a revert to an older version's content must record a NEW row");
        assert_eq!(bundle.content, a);
        assert_eq!(bundle.version, 3, "recorded as the new latest version");
        assert_eq!(bundle.published_by.as_deref(), Some(FILESYSTEM_ACTOR));
        assert_eq!(fake.bundles.lock().unwrap().len(), 3);
        // Now A is active: a second record of A is a no-op (it converged).
        assert!(
            fake.record_filesystem_snapshot("default", a)
                .await
                .unwrap()
                .is_none(),
            "now that A is active, re-record is a no-op",
        );
    }
}
