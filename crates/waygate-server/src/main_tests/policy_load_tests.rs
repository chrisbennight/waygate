//! Pins the file-as-truth precedence in [`resolve_policies`]: the
//! on-disk `policies/*.cedar` is the SOURCE OF TRUTH and wins, with the
//! durable store's active bundle consulted ONLY to RECOVER when the on-disk
//! set is unreadable. The recovery is the no-lockout invariant — a broken
//! on-disk set must never leave the gateway with no policy engine. (This
//! inverts a previous store-first precedence.)

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;
use waygate_policy::{
    PolicyBundle, PolicyBundleSummary, PolicyError, PolicyStatus, PolicyStore, SharedPolicyStore,
};

use super::resolve_policies;

/// Unique temp dir holding `.cedar` files, removed on drop.
struct TmpDir(PathBuf);
impl TmpDir {
    fn with_policy(body: &str) -> Self {
        let p = std::env::temp_dir().join(format!("polload-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("10-test.cedar"), body).unwrap();
        Self(p)
    }
    /// A dir whose `.cedar` file does not parse — simulates an unreadable
    /// on-disk set so the ledger-recovery path is exercised.
    fn broken() -> Self {
        Self::with_policy("this is not valid cedar {{{")
    }
}
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `active_bundle` returns the configured outcome; the other methods
/// are unreachable (load only calls `active_bundle`).
struct FakeStore(Result<String, PolicyError>);

impl FakeStore {
    fn bundle(content: &str) -> SharedPolicyStore {
        Arc::new(FakeStore(Ok(content.to_owned())))
    }
    fn err(e: PolicyError) -> SharedPolicyStore {
        Arc::new(FakeStore(Err(e)))
    }
    fn make_bundle(content: &str) -> PolicyBundle {
        PolicyBundle {
            id: Uuid::now_v7(),
            tenant_id: "default".into(),
            version: 7,
            status: PolicyStatus::Published,
            content: content.to_owned(),
            content_hash: waygate_policy::content_hash(content),
            tests: None,
            author: None,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            published_at: Some(time::OffsetDateTime::UNIX_EPOCH),
            published_by: Some("test".into()),
        }
    }
}

#[async_trait]
impl PolicyStore for FakeStore {
    async fn active_bundle(&self, _tenant: &str) -> Result<PolicyBundle, PolicyError> {
        match &self.0 {
            Ok(content) => Ok(Self::make_bundle(content)),
            Err(PolicyError::NotFound(m)) => Err(PolicyError::NotFound(m)),
            Err(_) => Err(PolicyError::NotFound("forced error stand-in")),
        }
    }
    async fn active_bundles(&self) -> Result<Vec<PolicyBundle>, PolicyError> {
        match self.active_bundle("default").await {
            Ok(bundle) => Ok(vec![bundle]),
            Err(PolicyError::NotFound(_)) => Ok(Vec::new()),
            Err(error) => Err(error),
        }
    }
    async fn list_bundles(&self, _t: &str) -> Result<Vec<PolicyBundleSummary>, PolicyError> {
        unreachable!("load path only calls active_bundle")
    }
    async fn get(&self, _t: &str, _id: Uuid) -> Result<PolicyBundle, PolicyError> {
        unreachable!("load path only calls active_bundle")
    }
    async fn create_draft(
        &self,
        _t: &str,
        _c: &str,
        _tests: Option<&serde_json::Value>,
        _a: Option<&str>,
    ) -> Result<PolicyBundle, PolicyError> {
        unreachable!("load path only calls active_bundle")
    }
    async fn publish(&self, _t: &str, _id: Uuid, _by: &str) -> Result<PolicyBundle, PolicyError> {
        unreachable!("load path only calls active_bundle")
    }
    async fn rollback_to(&self, _t: &str, _v: i32, _by: &str) -> Result<PolicyBundle, PolicyError> {
        unreachable!("load path only calls active_bundle")
    }
    async fn delete_all_bundles_for_tenant(&self, _t: &str) -> Result<u64, PolicyError> {
        unreachable!("load path only calls active_bundle")
    }
    async fn read_pointer(
        &self,
        _t: &str,
    ) -> Result<Option<waygate_policy::PolicyPointer>, PolicyError> {
        unreachable!("resolve_policies does not touch the turnstile pointer")
    }
    async fn seed_pointer(&self, _t: &str, _h: &str) -> Result<(), PolicyError> {
        unreachable!("resolve_policies does not touch the turnstile pointer")
    }
    async fn cas_pointer(
        &self,
        _t: &str,
        _expected: &str,
        _new: &str,
        _actor: &str,
    ) -> Result<waygate_policy::TurnstileOutcome, PolicyError> {
        unreachable!("resolve_policies does not touch the turnstile pointer")
    }
}

// Two distinct, both-valid policy sets so a count distinguishes
// which source won.
const ONE_POLICY: &str = "permit(principal, action, resource);\n";
const TWO_POLICIES: &str = "permit(principal, action, resource);\n\
                            forbid(principal, action, resource) when { false };\n";

#[tokio::test]
async fn no_store_loads_from_filesystem() {
    let dir = TmpDir::with_policy(ONE_POLICY);
    let resolved = resolve_policies(&dir.0, None).await.expect("fs load");
    assert_eq!(resolved.engine.list_policies().len(), 1);
    assert!(
        resolved.recovered.is_none(),
        "a clean disk load is not a recovery"
    );
}

#[tokio::test]
async fn filesystem_wins_over_store_bundle() {
    // File-as-truth: FS has one policy; the store's active bundle has two.
    // DISK must win, so the engine carries one policy and the store is never
    // consulted (no recovery).
    let dir = TmpDir::with_policy(ONE_POLICY);
    let store = FakeStore::bundle(TWO_POLICIES);
    let resolved = resolve_policies(&dir.0, Some(&store))
        .await
        .expect("disk load");
    assert_eq!(
        resolved.engine.list_policies().len(),
        1,
        "the on-disk policies dir is the source of truth and must win over the store",
    );
    assert!(
        resolved.recovered.is_none(),
        "a clean disk load must not be flagged as a ledger recovery",
    );
}

#[tokio::test]
async fn broken_disk_recovers_from_store_bundle() {
    // The on-disk set is unreadable; the store's active bundle (two policies)
    // recovers it rather than leaving the gateway with no policy engine.
    let dir = TmpDir::broken();
    let store = FakeStore::bundle(TWO_POLICIES);
    let resolved = resolve_policies(&dir.0, Some(&store))
        .await
        .expect("recover from ledger when disk is broken");
    assert_eq!(
        resolved.engine.list_policies().len(),
        2,
        "an unreadable on-disk set must recover from the ledger bundle",
    );
    assert!(
        resolved.recovered.is_some(),
        "a ledger recovery must be flagged for the stale-config signal",
    );
}

#[tokio::test]
async fn broken_disk_and_unparseable_store_errors() {
    // Disk broken AND the ledger bundle won't parse ⇒ no usable set; boot
    // fails loud rather than serving an empty policy engine.
    let dir = TmpDir::broken();
    let store = FakeStore::bundle("also not valid cedar }}}");
    assert!(
        resolve_policies(&dir.0, Some(&store)).await.is_err(),
        "no usable disk OR ledger set must be a hard error, never an empty engine",
    );
}

#[tokio::test]
async fn broken_disk_and_no_published_bundle_errors() {
    // Disk broken AND the store has no published bundle ⇒ nothing to recover
    // from ⇒ hard error.
    let dir = TmpDir::broken();
    let store = FakeStore::err(PolicyError::NotFound("none published"));
    assert!(
        resolve_policies(&dir.0, Some(&store)).await.is_err(),
        "a broken disk with no ledger bundle to recover from must be a hard error",
    );
}

#[tokio::test]
async fn broken_disk_and_no_store_errors() {
    // Disk broken AND no store wired (no DB) ⇒ hard error (no recovery
    // source at all).
    let dir = TmpDir::broken();
    assert!(
        resolve_policies(&dir.0, None).await.is_err(),
        "a broken disk with no store must be a hard error",
    );
}

// A policies dir that EXISTS and parses but contains ZERO policies
// (comment-only / empty volume). `CedarEngine::load_dir` compiles this to an
// empty deny-all engine; resolve_policies must NOT let it win.
const COMMENT_ONLY: &str = "// no policies here — mis-mounted volume\n";

#[tokio::test]
async fn empty_policies_dir_recovers_from_store() {
    // An existing-but-empty on-disk set must NOT win over a valid ledger
    // bundle — it recovers, like an unreadable set.
    let dir = TmpDir::with_policy(COMMENT_ONLY);
    let store = FakeStore::bundle(TWO_POLICIES);
    let resolved = resolve_policies(&dir.0, Some(&store))
        .await
        .expect("an empty on-disk set must recover from the ledger");
    assert_eq!(
        resolved.engine.list_policies().len(),
        2,
        "a zero-policy on-disk set must not win; recover the ledger bundle",
    );
    assert!(
        resolved.recovered.is_some(),
        "an empty-dir recovery must be flagged for the stale-config signal",
    );
}

#[tokio::test]
async fn empty_policies_dir_and_no_store_errors() {
    // An empty on-disk set with nothing to recover from must be a hard error,
    // never an installed empty (deny-all) engine.
    let dir = TmpDir::with_policy(COMMENT_ONLY);
    assert!(
        resolve_policies(&dir.0, None).await.is_err(),
        "an empty on-disk set with no ledger to recover from must be a hard error",
    );
}

#[tokio::test]
async fn broken_disk_and_empty_store_bundle_errors() {
    // A RECOVERED ledger bundle must also be non-empty. The publish/import
    // write paths only reject blank text + parse errors, so a zero-policy
    // bundle can exist; recovering it on a broken-disk boot would install
    // the same empty deny-all set. Must be a hard error.
    let dir = TmpDir::broken();
    let store = FakeStore::bundle(COMMENT_ONLY);
    assert!(
        resolve_policies(&dir.0, Some(&store)).await.is_err(),
        "a broken disk recovering an EMPTY ledger bundle must be a hard error, \
         never an installed empty engine",
    );
}

// ---- boot convergence: record_out_of_band_policy_snapshot ----

/// A stateful in-memory ledger: `active_bundle` / `create_draft` / `publish`
/// are real so the boot recorder can seed v1 and version drift; `read_pointer`
/// returns None (no in-flight write); the rest are unreachable on this path.
#[derive(Default)]
struct StatefulLedger {
    bundles: std::sync::Mutex<Vec<PolicyBundle>>,
}
impl StatefulLedger {
    fn published(content: &str) -> SharedPolicyStore {
        let s = StatefulLedger::default();
        s.bundles.lock().unwrap().push(PolicyBundle {
            id: Uuid::now_v7(),
            tenant_id: "default".into(),
            version: 1,
            status: PolicyStatus::Published,
            content: content.to_owned(),
            content_hash: waygate_policy::content_hash(content),
            tests: None,
            author: None,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            published_at: Some(time::OffsetDateTime::UNIX_EPOCH),
            published_by: Some("seed".into()),
        });
        Arc::new(s)
    }

    fn insert_published(&self, tenant: &str, version: i32, content: &str) {
        self.bundles.lock().unwrap().push(PolicyBundle {
            id: Uuid::now_v7(),
            tenant_id: tenant.to_owned(),
            version,
            status: PolicyStatus::Published,
            content: content.to_owned(),
            content_hash: waygate_policy::content_hash(content),
            tests: None,
            author: None,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            published_at: Some(time::OffsetDateTime::UNIX_EPOCH),
            published_by: Some("seed".into()),
        });
    }
}
#[async_trait]
impl PolicyStore for StatefulLedger {
    async fn active_bundle(&self, tenant: &str) -> Result<PolicyBundle, PolicyError> {
        self.bundles
            .lock()
            .unwrap()
            .iter()
            .filter(|b| b.tenant_id == tenant && matches!(b.status, PolicyStatus::Published))
            .max_by_key(|b| b.version)
            .cloned()
            .ok_or(PolicyError::NotFound("no published bundle"))
    }
    async fn active_bundles(&self) -> Result<Vec<PolicyBundle>, PolicyError> {
        let mut latest = std::collections::BTreeMap::<String, PolicyBundle>::new();
        for bundle in self
            .bundles
            .lock()
            .unwrap()
            .iter()
            .filter(|bundle| bundle.status == PolicyStatus::Published)
        {
            let slot = latest
                .entry(bundle.tenant_id.clone())
                .or_insert_with(|| bundle.clone());
            if bundle.version > slot.version {
                *slot = bundle.clone();
            }
        }
        Ok(latest.into_values().collect())
    }
    async fn create_draft(
        &self,
        tenant: &str,
        c: &str,
        _tests: Option<&serde_json::Value>,
        a: Option<&str>,
    ) -> Result<PolicyBundle, PolicyError> {
        let mut g = self.bundles.lock().unwrap();
        let version = g
            .iter()
            .filter(|bundle| bundle.tenant_id == tenant)
            .map(|b| b.version)
            .max()
            .unwrap_or(0)
            + 1;
        let b = PolicyBundle {
            id: Uuid::now_v7(),
            tenant_id: tenant.to_owned(),
            version,
            status: PolicyStatus::Draft,
            content: c.to_owned(),
            content_hash: waygate_policy::content_hash(c),
            tests: None,
            author: a.map(str::to_owned),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            published_at: None,
            published_by: None,
        };
        g.push(b.clone());
        Ok(b)
    }
    async fn publish(&self, _t: &str, id: Uuid, by: &str) -> Result<PolicyBundle, PolicyError> {
        let mut g = self.bundles.lock().unwrap();
        let b = g
            .iter_mut()
            .find(|b| b.id == id)
            .ok_or(PolicyError::NotFound("draft id"))?;
        b.status = PolicyStatus::Published;
        b.published_at = Some(time::OffsetDateTime::UNIX_EPOCH);
        b.published_by = Some(by.to_owned());
        Ok(b.clone())
    }
    async fn read_pointer(
        &self,
        _t: &str,
    ) -> Result<Option<waygate_policy::PolicyPointer>, PolicyError> {
        Ok(None)
    }
    async fn list_bundles(&self, _t: &str) -> Result<Vec<PolicyBundleSummary>, PolicyError> {
        unreachable!("boot recorder does not list")
    }
    async fn get(&self, _t: &str, _id: Uuid) -> Result<PolicyBundle, PolicyError> {
        unreachable!("boot recorder does not get-by-id")
    }
    async fn rollback_to(&self, _t: &str, _v: i32, _by: &str) -> Result<PolicyBundle, PolicyError> {
        unreachable!("boot recorder does not roll back")
    }
    async fn delete_all_bundles_for_tenant(&self, _t: &str) -> Result<u64, PolicyError> {
        unreachable!("boot recorder does not delete")
    }
    async fn seed_pointer(&self, _t: &str, _h: &str) -> Result<(), PolicyError> {
        unreachable!("the snapshot recorder only READS the pointer")
    }
    async fn cas_pointer(
        &self,
        _t: &str,
        _e: &str,
        _n: &str,
        _a: &str,
    ) -> Result<waygate_policy::TurnstileOutcome, PolicyError> {
        unreachable!("the snapshot recorder only READS the pointer")
    }
}

#[tokio::test]
async fn tenant_policy_snapshot_uses_latest_bundle_and_excludes_default() {
    let store = Arc::new(StatefulLedger::default());
    store.insert_published("default", 1, "permit (principal, action, resource);");
    store.insert_published("acme", 1, "forbid (principal, action, resource);");
    store.insert_published(
        "acme",
        2,
        "permit (principal, action, resource); forbid (principal, action, resource);",
    );
    store.insert_published("beta", 1, "permit (principal, action, resource);");
    let shared: SharedPolicyStore = store;

    let compiled = super::compile_tenant_policy_engines(Some(&shared))
        .await
        .expect("compile tenant registry");

    assert_eq!(compiled.engines.len(), 2, "default is file-backed");
    assert_eq!(
        compiled.engines["acme"].0.list_policies().len(),
        2,
        "the latest active bundle wins for a tenant",
    );
    assert_eq!(compiled.engines["beta"].0.list_policies().len(), 1);
}

#[tokio::test]
async fn tenant_policy_snapshot_rejects_corrupt_bundle_hash() {
    let store = Arc::new(StatefulLedger::default());
    store.insert_published("acme", 1, "permit (principal, action, resource);");
    store.bundles.lock().unwrap()[0].content_hash = "not-the-content-hash".to_owned();
    let shared: SharedPolicyStore = store;

    let error = super::compile_tenant_policy_engines(Some(&shared))
        .await
        .err()
        .expect("hash mismatch must fail closed");
    assert!(error.to_string().contains("hash mismatch"));
}

fn null_audit() -> waygate_mcp::SharedEvidence {
    Arc::new(waygate_mcp::NullSink)
}

#[tokio::test]
async fn boot_seeds_v1_when_ledger_is_empty() {
    // The fix: a clean-disk boot with NO active bundle seeds the initial
    // ledger from disk (instead of deferring to a manual --import-policies),
    // so the dashboard editor — which gates on an active bundle — works.
    let dir = TmpDir::with_policy(ONE_POLICY);
    let store: SharedPolicyStore = Arc::new(StatefulLedger::default());
    assert!(
        store.active_bundle("default").await.is_err(),
        "precondition: no active bundle"
    );
    super::record_out_of_band_policy_snapshot(&store, &dir.0, &null_audit()).await;
    let active = store
        .active_bundle("default")
        .await
        .expect("boot seeded an initial published bundle");
    assert_eq!(active.version, 1);
    assert!(
        active
            .content
            .contains("permit(principal, action, resource)"),
        "seeded bundle carries the on-disk policy"
    );
}

#[tokio::test]
async fn boot_captures_drift_as_a_new_version() {
    // Unchanged behavior: an active bundle that differs from disk is captured
    // as a new filesystem-attributed version (disk wins).
    let store = StatefulLedger::published("permit(principal, action, resource);");
    let dir = TmpDir::with_policy(TWO_POLICIES);
    super::record_out_of_band_policy_snapshot(&store, &dir.0, &null_audit()).await;
    let active = store.active_bundle("default").await.unwrap();
    assert_eq!(active.version, 2, "disk drift recorded as a new version");
    assert!(
        active.content.contains("forbid"),
        "converged to the on-disk set"
    );
}

#[tokio::test]
async fn boot_is_noop_when_disk_matches_active() {
    // Unchanged behavior: disk == active → no new version.
    let store = StatefulLedger::published("permit(principal, action, resource);");
    let dir = TmpDir::with_policy(ONE_POLICY);
    super::record_out_of_band_policy_snapshot(&store, &dir.0, &null_audit()).await;
    let active = store.active_bundle("default").await.unwrap();
    assert_eq!(active.version, 1, "no new version when disk matches active");
}
