//! Pins the file-as-truth precedence in [`resolve_manifests`] (inverting
//! the previous dual-read design): the on-disk `servers/*.yaml` dir is
//! the source of truth, and the durable store's newest snapshot is
//! consulted ONLY as recovery when the on-disk set is unreadable. The
//! recovery is the no-lockout invariant in its current direction — a
//! single broken `*.yaml` must never leave the gateway with no upstream
//! set — but a clean on-disk load (even an empty one) wins outright and
//! the store is not read.
//! Exercises the real wiring with no Postgres (the live DB path is
//! the opt-in `pg_smoke` test).

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;
use waygate_manifest_store::{
    content_hash, ManifestBundle, ManifestBundleSummary, ManifestError, ManifestStatus,
    ManifestStore, SharedManifestStore,
};

use super::resolve_manifests;
#[cfg(unix)]
use super::{reload_manifests_only, ReloadDeps};
#[cfg(unix)]
use std::collections::BTreeMap;
#[cfg(unix)]
use waygate_upstream::{load_manifests, pool::UpstreamPool};

/// Canonical content hash of a manifest-set YAML string, the way disk is
/// hashed — local helper for the drift-detection tests.
fn canon_hash(content: &str) -> String {
    content_hash(
        &waygate_upstream::serialize_manifest_set(
            &waygate_upstream::parse_manifest_set(content).unwrap(),
        )
        .unwrap(),
    )
}

#[test]
fn disk_not_drifted_when_active_matches_disk() {
    let content = "- name: a\n  transport: http\n  url: http://a/mcp\n";
    assert!(!super::disk_drifted_from_active(
        content,
        &canon_hash(content)
    ));
}

#[test]
fn disk_drifted_when_active_differs_from_disk() {
    let active = "- name: a\n  transport: http\n  url: http://a/mcp\n";
    let disk = "- name: b\n  transport: http\n  url: http://b/mcp\n";
    assert!(super::disk_drifted_from_active(active, &canon_hash(disk)));
}

#[test]
fn disk_not_drifted_for_noncanonical_equivalent_active() {
    // The active row stored a NON-canonical serialization (leading comment,
    // fields reordered) of the same set that is on disk. It must NOT read as
    // drift — else every reload would synthesize a spurious filesystem row
    // (the same canonical-vs-raw subtlety as the turnstile).
    let disk = "- name: a\n  transport: http\n  url: http://a/mcp\n";
    let active_noncanonical = "# staged\n- url: http://a/mcp\n  transport: http\n  name: a\n";
    assert!(!super::disk_drifted_from_active(
        active_noncanonical,
        &canon_hash(disk)
    ));
}

#[test]
fn disk_not_drifted_when_active_content_unparseable() {
    // Don't synthesize a convergence row off an unparseable ledger row.
    assert!(!super::disk_drifted_from_active(
        "this is not: [[[ valid manifest yaml",
        &content_hash("whatever"),
    ));
}

fn pointer_at(updated_at: time::OffsetDateTime) -> waygate_manifest_store::ManifestPointer {
    waygate_manifest_store::ManifestPointer {
        tenant_id: "default".into(),
        current_hash: "h".into(),
        updated_at,
        updated_by: None,
    }
}

#[test]
fn write_in_flight_true_for_a_recently_advanced_pointer() {
    // A coordinated write CASed the pointer moments ago and may be mid
    // mirror-to-ledger — synthesis must defer so it doesn't record the
    // operator's in-flight publish as a filesystem row.
    let now = time::OffsetDateTime::now_utc();
    let p = pointer_at(now); // just advanced
    assert!(super::write_in_flight(Some(&p), now));
}

#[test]
fn write_in_flight_false_for_a_settled_pointer() {
    // An out-of-band edit leaves the pointer at the last coordinated write's
    // (old) timestamp — well past the grace window ⇒ record.
    let now = time::OffsetDateTime::now_utc();
    let p = pointer_at(now - waygate_manifest_store::RECONCILE_GRACE - time::Duration::seconds(1));
    assert!(!super::write_in_flight(Some(&p), now));
}

#[test]
fn write_in_flight_false_when_no_pointer() {
    // Fresh deploy / no pointer ⇒ no coordinated write in flight.
    assert!(!super::write_in_flight(
        None,
        time::OffsetDateTime::now_utc()
    ));
}

#[test]
fn replica_id_prefers_explicit_then_hostname_then_pid() {
    // Explicit override wins.
    assert_eq!(super::pick_replica_id(Some("r1"), Some("pod-7"), 5), "r1");
    // Else the container/pod HOSTNAME.
    assert_eq!(super::pick_replica_id(None, Some("pod-7"), 5), "pod-7");
    // A blank explicit/hostname is ignored (falls through).
    assert_eq!(
        super::pick_replica_id(Some("   "), Some("pod-7"), 5),
        "pod-7"
    );
    assert_eq!(super::pick_replica_id(None, Some(""), 42), "replica-pid42");
    // Local/dev fallback: process-scoped, so two local instances differ.
    assert_eq!(super::pick_replica_id(None, None, 42), "replica-pid42");
}

/// Unique temp dir holding one `*.yaml` manifest, removed on drop.
/// `load_manifests` reads one manifest per file, so a single file is
/// a one-upstream filesystem set.
struct TmpDir(PathBuf);
impl TmpDir {
    fn with_one_manifest() -> Self {
        let p = std::env::temp_dir().join(format!("manifestload-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(
            p.join("gamma.yaml"),
            "name: gamma\ntransport: http\nurl: http://gamma/mcp\n",
        )
        .unwrap();
        Self(p)
    }
    /// An empty dir is a valid zero-upstream filesystem set.
    fn empty() -> Self {
        let p = std::env::temp_dir().join(format!("manifestload-empty-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    /// A dir with one *.yaml that doesn't deserialize as an
    /// `UpstreamManifest` (missing the required `name`), so
    /// `load_manifests` errors — the trigger for ledger recovery.
    fn with_broken_manifest() -> Self {
        let p = std::env::temp_dir().join(format!("manifestload-broken-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(
            p.join("broken.yaml"),
            "transport: http\nurl: http://broken/mcp\n",
        )
        .unwrap();
        Self(p)
    }
}
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `active_bundle` and `read_pointer` return configured outcomes; the other
/// methods are unreachable in manifest resolution and reload tests.
struct FakeStore {
    active: Result<String, ManifestError>,
    pointer: Option<waygate_manifest_store::ManifestPointer>,
}

impl FakeStore {
    fn bundle(content: &str) -> SharedManifestStore {
        Arc::new(FakeStore {
            active: Ok(content.to_owned()),
            pointer: None,
        })
    }
    fn bundle_with_pointer(
        content: &str,
        pointer: waygate_manifest_store::ManifestPointer,
    ) -> SharedManifestStore {
        Arc::new(FakeStore {
            active: Ok(content.to_owned()),
            pointer: Some(pointer),
        })
    }
    fn err(e: ManifestError) -> SharedManifestStore {
        Arc::new(FakeStore {
            active: Err(e),
            pointer: None,
        })
    }
    fn make_bundle(content: &str) -> ManifestBundle {
        ManifestBundle {
            id: Uuid::now_v7(),
            tenant_id: "default".into(),
            version: 7,
            status: ManifestStatus::Published,
            content: content.to_owned(),
            content_hash: content_hash(content),
            author: None,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            published_at: Some(time::OffsetDateTime::UNIX_EPOCH),
            published_by: Some("test".into()),
        }
    }
}

#[async_trait]
impl ManifestStore for FakeStore {
    async fn active_bundle(&self, _tenant: &str) -> Result<ManifestBundle, ManifestError> {
        match &self.active {
            Ok(content) => Ok(Self::make_bundle(content)),
            // Reconstruct the configured error faithfully so a
            // non-NotFound error reaches resolve_manifests's generic
            // `Err(e)` arm rather than being collapsed to NotFound — the
            // db_error test must actually exercise that branch.
            // `ManifestError` isn't `Clone` — its `Database` variant wraps
            // a non-`Clone` `sqlx::Error` — so the two test-relevant
            // variants are rebuilt by hand; `Database` is never
            // configured by these tests.
            Err(ManifestError::NotFound(m)) => Err(ManifestError::NotFound(m)),
            Err(ManifestError::UnknownStatus(s)) => Err(ManifestError::UnknownStatus(s.clone())),
            Err(ManifestError::Database(_)) => Err(ManifestError::NotFound(
                "database-variant stand-in (unused in tests)",
            )),
        }
    }
    async fn list_bundles(&self, _t: &str) -> Result<Vec<ManifestBundleSummary>, ManifestError> {
        unreachable!("resolver only calls active_bundle")
    }
    async fn get(&self, _t: &str, _id: Uuid) -> Result<ManifestBundle, ManifestError> {
        unreachable!("resolver only calls active_bundle")
    }
    async fn create_draft(
        &self,
        _t: &str,
        _c: &str,
        _a: Option<&str>,
    ) -> Result<ManifestBundle, ManifestError> {
        unreachable!("resolver only calls active_bundle")
    }
    async fn publish(
        &self,
        _t: &str,
        _id: Uuid,
        _by: &str,
    ) -> Result<ManifestBundle, ManifestError> {
        unreachable!("resolver only calls active_bundle")
    }
    async fn rollback_to(
        &self,
        _t: &str,
        _v: i32,
        _by: &str,
    ) -> Result<ManifestBundle, ManifestError> {
        unreachable!("resolver only calls active_bundle")
    }
    async fn delete_all_for_tenant(&self, _t: &str) -> Result<u64, ManifestError> {
        unreachable!("resolver only calls active_bundle")
    }
    async fn read_pointer(
        &self,
        _t: &str,
    ) -> Result<Option<waygate_manifest_store::ManifestPointer>, ManifestError> {
        Ok(self.pointer.clone())
    }
    async fn seed_pointer(&self, _t: &str, _hash: &str) -> Result<(), ManifestError> {
        unreachable!("resolver only calls active_bundle")
    }
    async fn cas_pointer(
        &self,
        _t: &str,
        _expected: &str,
        _new: &str,
        _actor: &str,
    ) -> Result<waygate_manifest_store::TurnstileOutcome, ManifestError> {
        unreachable!("resolver only calls active_bundle")
    }
}

// A two-upstream bundle so a count distinguishes which source won:
// the store set has two, the filesystem dir has one.
const TWO_UPSTREAMS: &str = "- name: alpha\n  transport: http\n  url: http://alpha/mcp\n\
                             - name: beta\n  transport: http\n  url: http://beta/mcp\n";

#[tokio::test]
async fn no_store_loads_from_filesystem() {
    let dir = TmpDir::with_one_manifest();
    let resolved = resolve_manifests(&dir.0, None).await.expect("fs load");
    assert_eq!(resolved.manifests.len(), 1);
    assert!(resolved.manifests.contains_key("gamma"));
    assert!(
        resolved.recovered.is_none(),
        "a clean on-disk load is healthy, not a recovery",
    );
}

#[tokio::test]
async fn filesystem_wins_over_store_bundle() {
    // FS has one upstream; the store's snapshot has two. Under
    // file-as-truth the on-disk set wins and the store is NOT read,
    // so the resolved set carries the single filesystem upstream.
    let dir = TmpDir::with_one_manifest();
    let store = FakeStore::bundle(TWO_UPSTREAMS);
    let resolved = resolve_manifests(&dir.0, Some(&store))
        .await
        .expect("fs load");
    assert_eq!(
        resolved.manifests.len(),
        1,
        "the on-disk set is the source of truth and wins over the store",
    );
    assert!(resolved.manifests.contains_key("gamma"));
    assert!(
        resolved.recovered.is_none(),
        "a clean on-disk load wins without recovery — healthy",
    );
}

#[tokio::test]
async fn empty_filesystem_dir_is_authoritative_over_store() {
    // A clean empty dir is a valid zero-upstream set and wins
    // outright — it must NOT trigger store recovery, even though the
    // store's snapshot would yield two upstreams were it consulted.
    let dir = TmpDir::empty();
    let store = FakeStore::bundle(TWO_UPSTREAMS);
    let resolved = resolve_manifests(&dir.0, Some(&store))
        .await
        .expect("empty fs load");
    assert!(
        resolved.manifests.is_empty(),
        "an empty on-disk dir is authoritative, not a recovery trigger",
    );
    assert!(
        resolved.recovered.is_none(),
        "an authoritative empty dir is healthy, not a recovery",
    );
}

#[tokio::test]
async fn broken_filesystem_recovers_from_store_snapshot() {
    // A malformed *.yaml makes load_manifests error; rather than
    // blank the upstream set, recover from the newest ledger snapshot
    // (no-lockout, new direction).
    let dir = TmpDir::with_broken_manifest();
    let store = FakeStore::bundle(TWO_UPSTREAMS);
    let resolved = resolve_manifests(&dir.0, Some(&store))
        .await
        .expect("recovered from ledger snapshot");
    assert_eq!(
        resolved.manifests.len(),
        2,
        "recovered the two-upstream snapshot",
    );
    assert!(resolved.manifests.contains_key("alpha") && resolved.manifests.contains_key("beta"));
    assert!(
        resolved.recovered.is_some(),
        "a ledger recovery must be flagged so the config-health banner shows degraded",
    );
}

#[tokio::test]
async fn interrupted_manifest_write_recovers_from_store_snapshot() {
    let dir = TmpDir::with_one_manifest();
    std::fs::write(
        dir.0.join(waygate_upstream::MANIFEST_WRITE_MARKER),
        "manifest write in progress\n",
    )
    .unwrap();
    let store = FakeStore::bundle(TWO_UPSTREAMS);

    let resolved = resolve_manifests(&dir.0, Some(&store))
        .await
        .expect("the marker must route the incomplete directory to ledger recovery");

    assert_eq!(
        resolved.manifests.keys().cloned().collect::<Vec<_>>(),
        ["alpha", "beta"],
    );
    assert!(
        resolved.recovered.is_some(),
        "serving a prior complete snapshot must remain operator-visible",
    );
}

#[tokio::test]
async fn broken_filesystem_no_store_propagates_error() {
    // Unreadable on-disk set and no store to recover from ⇒ fail
    // loud rather than serve nothing.
    let dir = TmpDir::with_broken_manifest();
    assert!(
        resolve_manifests(&dir.0, None).await.is_err(),
        "a broken file with no recovery source must propagate the error",
    );
}

#[tokio::test]
async fn broken_filesystem_store_notfound_propagates_error() {
    // Unreadable on-disk set and no published snapshot ⇒ error.
    let dir = TmpDir::with_broken_manifest();
    let store = FakeStore::err(ManifestError::NotFound("none published"));
    assert!(resolve_manifests(&dir.0, Some(&store)).await.is_err());
}

#[tokio::test]
async fn broken_filesystem_store_error_propagates_error() {
    // Unreadable on-disk set and a *non-NotFound* store error (a real
    // DB outage surfaces as the `Database` variant; `UnknownStatus`
    // stands in here) ⇒ error: this exercises the generic `Err(e)`
    // recovery arm distinct from the NotFound arm.
    let dir = TmpDir::with_broken_manifest();
    let store = FakeStore::err(ManifestError::UnknownStatus("non-notfound-stand-in".into()));
    assert!(resolve_manifests(&dir.0, Some(&store)).await.is_err());
}

#[tokio::test]
async fn broken_filesystem_unparseable_snapshot_propagates_error() {
    // Unreadable on-disk set AND a snapshot that won't parse ⇒ error;
    // there is no usable recovery source.
    let dir = TmpDir::with_broken_manifest();
    let store = FakeStore::bundle("this is not valid manifest yaml: [[[");
    assert!(resolve_manifests(&dir.0, Some(&store)).await.is_err());
}

#[tokio::test]
async fn missing_filesystem_dir_recovers_from_store_snapshot() {
    // A *missing* dir (unmounted volume, typoed path) must NOT be
    // treated as an authoritative empty set — load_manifests would
    // return Ok(empty) for it, so resolve_manifests guards is_dir and
    // routes it to ledger recovery exactly like a malformed file.
    let missing = std::env::temp_dir().join(format!("manifestload-missing-{}", Uuid::now_v7()));
    assert!(!missing.exists());
    let store = FakeStore::bundle(TWO_UPSTREAMS);
    let resolved = resolve_manifests(&missing, Some(&store))
        .await
        .expect("recovered from ledger snapshot on a missing dir");
    assert_eq!(resolved.manifests.len(), 2);
    assert!(resolved.manifests.contains_key("alpha") && resolved.manifests.contains_key("beta"));
    assert!(
        resolved.recovered.is_some(),
        "a missing-dir recovery is degraded, not a clean load",
    );
}

#[tokio::test]
async fn missing_filesystem_dir_no_store_propagates_error() {
    // Missing dir and no store to recover from ⇒ fail loud, never a
    // silent zero-upstream set.
    let missing = std::env::temp_dir().join(format!("manifestload-missing-{}", Uuid::now_v7()));
    assert!(!missing.exists());
    let error = match resolve_manifests(&missing, None).await {
        Err(error) => error,
        Ok(_) => panic!("a missing live dir without a ledger must fail loud"),
    };
    assert!(
        error.to_string().contains("no usable ledger snapshot"),
        "the error must name the exhausted recovery boundary: {error:#}",
    );
}

#[tokio::test]
async fn no_store_empty_dir_is_empty_set() {
    // No store, empty dir ⇒ empty set (no upstreams), not an error.
    let dir = TmpDir::empty();
    let resolved = resolve_manifests(&dir.0, None).await.expect("empty fs");
    assert!(resolved.manifests.is_empty());
    assert!(resolved.recovered.is_none());
}

// --- The lean doorbell/poll manifest reload (reload_manifests_only) ---

#[cfg(unix)]
fn reload_deps_for(
    dir: &std::path::Path,
    pool: std::sync::Arc<UpstreamPool>,
    config_health: waygate_upstream::SharedConfigHealth,
) -> ReloadDeps {
    ReloadDeps {
        policies_dir: dir.to_path_buf(),
        servers_dir: dir.to_path_buf(),
        cedar: None,
        policy_store: None,
        manifest_store: None,
        pool,
        audit: std::sync::Arc::new(waygate_mcp::audit::NullSink),
        deployment_profile: crate::config::DeploymentProfile::Dev,
        config_health,
        // `cedar: None` ⇒ reload_policies_only returns before reading this.
        policy_config_health: std::sync::Arc::new(waygate_upstream::ConfigHealth::default()),
        replica_id: "test-replica".to_owned(),
        db_pool: None,
        last_policy_hash: std::sync::Mutex::new(None),
        last_tenant_policy_hash: std::sync::Mutex::new(None),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn reload_manifests_only_clean_load_marks_healthy() {
    // The doorbell/poll path on a clean on-disk set: swap the pool and flip
    // config-health to healthy (clearing any prior stale banner) without the
    // Cedar rebuild the SIGHUP path does.
    let dir = TmpDir::with_one_manifest();
    let manifests = load_manifests(&dir.0).unwrap();
    let pool = std::sync::Arc::new(UpstreamPool::from_manifests_disconnected(manifests));
    let ch: waygate_upstream::SharedConfigHealth =
        std::sync::Arc::new(waygate_upstream::ConfigHealth::default());
    ch.set_degraded("stale — pre-reload");
    let deps = reload_deps_for(&dir.0, pool, ch.clone());
    reload_manifests_only(&deps).await;
    assert!(
        ch.snapshot().expect("health set").healthy,
        "a clean disk reload must mark config-health healthy",
    );
}

#[cfg(unix)]
#[tokio::test]
async fn reload_manifests_only_unreadable_dir_keeps_degraded() {
    // A broken on-disk set with no ledger ⇒ fail-closed: keep the previous
    // pool, mark config-health degraded (never downgrade to baked here).
    let dir = TmpDir::with_broken_manifest();
    let pool = std::sync::Arc::new(UpstreamPool::from_manifests_disconnected(BTreeMap::new()));
    let ch: waygate_upstream::SharedConfigHealth =
        std::sync::Arc::new(waygate_upstream::ConfigHealth::default());
    ch.set_healthy("was fine");
    let deps = reload_deps_for(&dir.0, pool, ch.clone());
    reload_manifests_only(&deps).await;
    assert!(
        !ch.snapshot().expect("health set").healthy,
        "an unreadable live dir must mark config-health degraded",
    );
}

#[cfg(unix)]
#[tokio::test]
async fn reload_manifests_only_defers_a_partial_coordinated_write() {
    let dir = TmpDir::with_one_manifest();
    std::fs::write(
        dir.0.join(waygate_upstream::MANIFEST_WRITE_MARKER),
        "manifest write in progress\n",
    )
    .unwrap();
    let prior = waygate_upstream::parse_manifest_set(TWO_UPSTREAMS).unwrap();
    let pool = std::sync::Arc::new(UpstreamPool::from_manifests_disconnected(prior));
    let ch: waygate_upstream::SharedConfigHealth =
        std::sync::Arc::new(waygate_upstream::ConfigHealth::default());
    ch.set_healthy("serving the prior complete set");
    let mut pointer = pointer_at(time::OffsetDateTime::now_utc());
    pointer.current_hash =
        canon_hash("- name: delta\n  transport: http\n  url: http://delta/mcp\n");
    let store = FakeStore::bundle_with_pointer(TWO_UPSTREAMS, pointer);
    let mut deps = reload_deps_for(&dir.0, pool.clone(), ch.clone());
    deps.manifest_store = Some(store);

    reload_manifests_only(&deps).await;

    let mut names: Vec<_> = pool
        .manifests()
        .into_iter()
        .map(|manifest| manifest.name)
        .collect();
    names.sort();
    assert_eq!(
        names,
        ["alpha", "beta"],
        "a reload that catches a partial filesystem commit must retain the prior complete set",
    );
    assert!(
        ch.snapshot().expect("health remains set").healthy,
        "an expected in-flight commit must not mark the prior serving set unhealthy",
    );
}

/// The generation-fenced reconcile latch contract: an arm owes a
/// reconcile; settling the generation observed BEFORE the reconcile began
/// disarms it; and an arm that lands between observe and settle survives —
/// a stale success must never clear a newer obligation, or a background
/// reconcile racing a dashboard reload could commit stale classifications
/// and silence the retry that would repair them.
#[test]
fn catalog_reconcile_latch_contract() {
    let latch = super::ReconcileLatch::new();
    assert!(!latch.due(), "a fresh latch owes nothing");
    latch.arm();
    assert!(latch.due(), "an armed latch owes a reconcile");
    let observed = latch.observe();
    latch.settle(observed);
    assert!(!latch.due(), "settling the observed generation disarms");

    let observed = latch.observe();
    latch.arm();
    latch.settle(observed);
    assert!(
        latch.due(),
        "an arm between observe and settle must survive the stale success",
    );

    let observed = latch.observe();
    latch.settle(observed);
    assert!(!latch.due(), "a fresh observation settles the newer arm");
}
