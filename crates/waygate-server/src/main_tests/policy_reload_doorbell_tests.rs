//! Pins the change-detection contract of the policy doorbell/poll
//! reload ([`super::reload_policies_only`]): it swaps the live Cedar engine to
//! match disk on a real change, is a NO-OP (no engine swap, no `PolicyReload`
//! audit) when disk is unchanged, and picks up a later change. No Postgres —
//! `policy_store: None`, so `resolve_policies` loads purely from the on-disk
//! set and the clean-load snapshot/reconcile (which need the ledger) are
//! skipped. The no-op is observed via `Arc::ptr_eq` on the engine snapshot: a
//! no-op returns before `engine.reload`, so the inner `Arc` is unchanged.
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use uuid::Uuid;
use waygate_authz::ReloadableCedar;
use waygate_upstream::pool::UpstreamPool;

use super::{compile_policy_source, load_cedar_from_dir, reload_policies_only, ReloadDeps};

struct TmpDir(PathBuf);
impl TmpDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("poldoor-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn write(&self, name: &str, body: &str) {
        std::fs::write(self.0.join(name), body).unwrap();
    }
}
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn captured_policy_source_is_compiled_without_rereading_disk() {
    let dir = TmpDir::new();
    dir.write("10-first.cedar", "permit(principal, action, resource);");
    let captured = waygate_policy::read_policy_dir(&dir.0).expect("capture policy source");

    // A newer valid write lands after the reload captured the source and hash.
    // Compiling that reload must still produce the captured generation; the
    // next tick will observe and publish the newer disk generation once.
    dir.write("20-newer.cedar", "forbid(principal, action, resource);");
    let compiled = compile_policy_source(&dir.0, &captured.source).expect("compile capture");

    assert_eq!(compiled.list_policies().len(), 1);
    assert_eq!(
        load_cedar_from_dir(&dir.0)
            .expect("compile current disk")
            .list_policies()
            .len(),
        2,
        "the test must prove disk changed after the capture",
    );
}

fn deps_with(dir: &std::path::Path, engine: Arc<ReloadableCedar>) -> ReloadDeps {
    ReloadDeps {
        policies_dir: dir.to_path_buf(),
        servers_dir: dir.to_path_buf(),
        cedar: Some(engine),
        policy_store: None,
        manifest_store: None,
        pool: Arc::new(UpstreamPool::from_manifests_disconnected(BTreeMap::new())),
        audit: Arc::new(waygate_mcp::audit::NullSink),
        deployment_profile: crate::config::DeploymentProfile::Dev,
        config_health: Arc::new(waygate_upstream::ConfigHealth::default()),
        policy_config_health: Arc::new(waygate_upstream::ConfigHealth::default()),
        replica_id: "test-replica".to_owned(),
        db_pool: None,
        last_policy_hash: Mutex::new(None),
        last_tenant_policy_hash: Mutex::new(None),
    }
}

struct TenantSnapshotStore {
    default_bundle: Option<waygate_policy::PolicyBundle>,
    bundles: Vec<waygate_policy::PolicyBundle>,
    full_snapshot_reads: Arc<std::sync::atomic::AtomicUsize>,
    full_snapshot_started: Option<Arc<tokio::sync::Semaphore>>,
    full_snapshot_release: Option<Arc<tokio::sync::Semaphore>>,
}

#[async_trait::async_trait]
impl waygate_policy::PolicyStore for TenantSnapshotStore {
    async fn active_bundle(
        &self,
        tenant: &str,
    ) -> Result<waygate_policy::PolicyBundle, waygate_policy::PolicyError> {
        if tenant == waygate_core::TenantId::DEFAULT {
            self.default_bundle
                .clone()
                .ok_or(waygate_policy::PolicyError::NotFound(
                    "no default recovery bundle",
                ))
        } else {
            Err(waygate_policy::PolicyError::NotFound("snapshot-only fake"))
        }
    }

    async fn active_bundles(
        &self,
    ) -> Result<Vec<waygate_policy::PolicyBundle>, waygate_policy::PolicyError> {
        self.full_snapshot_reads
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if let Some(started) = &self.full_snapshot_started {
            started.add_permits(1);
        }
        if let Some(release) = &self.full_snapshot_release {
            release.acquire().await.expect("release semaphore").forget();
        }
        Ok(self.bundles.clone())
    }

    async fn active_bundle_signatures(
        &self,
    ) -> Result<Vec<waygate_policy::ActivePolicyBundleSignature>, waygate_policy::PolicyError> {
        Ok(self
            .bundles
            .iter()
            .map(|bundle| waygate_policy::ActivePolicyBundleSignature {
                tenant_id: bundle.tenant_id.clone(),
                content_hash: bundle.content_hash.clone(),
            })
            .collect())
    }

    async fn list_bundles(
        &self,
        _tenant: &str,
    ) -> Result<Vec<waygate_policy::PolicyBundleSummary>, waygate_policy::PolicyError> {
        unimplemented!("tenant refresh only reads active_bundles")
    }

    async fn get(
        &self,
        _tenant: &str,
        _id: Uuid,
    ) -> Result<waygate_policy::PolicyBundle, waygate_policy::PolicyError> {
        unimplemented!("tenant refresh only reads active_bundles")
    }

    async fn create_draft(
        &self,
        _tenant: &str,
        _content: &str,
        _tests: Option<&serde_json::Value>,
        _author: Option<&str>,
    ) -> Result<waygate_policy::PolicyBundle, waygate_policy::PolicyError> {
        unimplemented!("tenant refresh only reads active_bundles")
    }

    async fn publish(
        &self,
        _tenant: &str,
        _id: Uuid,
        _publisher: &str,
    ) -> Result<waygate_policy::PolicyBundle, waygate_policy::PolicyError> {
        unimplemented!("tenant refresh only reads active_bundles")
    }

    async fn rollback_to(
        &self,
        _tenant: &str,
        _version: i32,
        _actor: &str,
    ) -> Result<waygate_policy::PolicyBundle, waygate_policy::PolicyError> {
        unimplemented!("tenant refresh only reads active_bundles")
    }

    async fn delete_all_bundles_for_tenant(
        &self,
        _tenant: &str,
    ) -> Result<u64, waygate_policy::PolicyError> {
        unimplemented!("tenant refresh only reads active_bundles")
    }

    async fn read_pointer(
        &self,
        _tenant: &str,
    ) -> Result<Option<waygate_policy::PolicyPointer>, waygate_policy::PolicyError> {
        unimplemented!("tenant refresh only reads active_bundles")
    }

    async fn seed_pointer(
        &self,
        _tenant: &str,
        _hash: &str,
    ) -> Result<(), waygate_policy::PolicyError> {
        unimplemented!("tenant refresh only reads active_bundles")
    }

    async fn cas_pointer(
        &self,
        _tenant: &str,
        _expected_hash: &str,
        _new_hash: &str,
        _actor: &str,
    ) -> Result<waygate_policy::TurnstileOutcome, waygate_policy::PolicyError> {
        unimplemented!("tenant refresh only reads active_bundles")
    }
}

fn tenant_bundle(tenant: &str, content: &str) -> waygate_policy::PolicyBundle {
    waygate_policy::PolicyBundle {
        id: Uuid::now_v7(),
        tenant_id: tenant.to_owned(),
        version: 1,
        status: waygate_policy::PolicyStatus::Published,
        content: content.to_owned(),
        content_hash: waygate_policy::content_hash(content),
        tests: None,
        author: None,
        created_at: time::OffsetDateTime::UNIX_EPOCH,
        published_at: Some(time::OffsetDateTime::UNIX_EPOCH),
        published_by: Some("test".to_owned()),
    }
}

struct BlockingAudit {
    started: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
}

impl BlockingAudit {
    fn new() -> Self {
        Self {
            started: tokio::sync::Semaphore::new(0),
            release: tokio::sync::Semaphore::new(0),
        }
    }
}

#[async_trait::async_trait]
impl waygate_mcp::EvidenceRecorder for BlockingAudit {
    async fn record_required(
        &self,
        _event: waygate_mcp::AuditEvent,
    ) -> Result<Uuid, waygate_mcp::EvidenceError> {
        unimplemented!("policy reload uses best-effort audit")
    }

    async fn record_chained_best_effort(&self, _event: waygate_mcp::AuditEvent) {
        unimplemented!("policy reload uses unchained best-effort audit")
    }

    async fn record_best_effort(&self, _event: waygate_mcp::AuditEvent) {
        self.started.add_permits(1);
        self.release
            .acquire()
            .await
            .expect("audit release semaphore")
            .forget();
    }
}

#[tokio::test]
async fn failed_tenant_refresh_keeps_the_previous_registry() {
    let dir = TmpDir::new();
    dir.write("10-default.cedar", "forbid(principal, action, resource);");
    let engine = Arc::new(ReloadableCedar::new(load_cedar_from_dir(&dir.0).unwrap()));
    engine.replace_tenants(HashMap::from([(
        "acme".to_owned(),
        waygate_authz::CedarEngine::from_source("permit(principal, action, resource);").unwrap(),
    )]));
    let before = engine.snapshot_for_tenant("acme");

    let mut corrupt = tenant_bundle("acme", "forbid(principal, action, resource);");
    corrupt.content_hash = "wrong".to_owned();
    let mut deps = deps_with(&dir.0, engine.clone());
    deps.policy_store = Some(Arc::new(TenantSnapshotStore {
        default_bundle: None,
        bundles: vec![corrupt],
        full_snapshot_reads: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        full_snapshot_started: None,
        full_snapshot_release: None,
    }));

    let error = super::refresh_tenant_policy_engines(&deps)
        .await
        .expect_err("corrupt tenant bundle must fail closed");
    assert!(error.to_string().contains("hash mismatch"));
    assert!(
        Arc::ptr_eq(&before, &engine.snapshot_for_tenant("acme")),
        "a failed refresh must keep the previous tenant engine",
    );
    assert!(
        deps.last_tenant_policy_hash.lock().unwrap().is_none(),
        "a failed refresh remains due for retry",
    );
}

#[tokio::test]
async fn tenant_refresh_removes_absent_bundle_and_then_noops() {
    let dir = TmpDir::new();
    dir.write("10-default.cedar", "forbid(principal, action, resource);");
    let engine = Arc::new(ReloadableCedar::new(load_cedar_from_dir(&dir.0).unwrap()));
    engine.replace_tenants(HashMap::from([(
        "acme".to_owned(),
        waygate_authz::CedarEngine::from_source("permit(principal, action, resource);").unwrap(),
    )]));
    let default = engine.snapshot();
    let mut deps = deps_with(&dir.0, engine.clone());
    let full_snapshot_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    deps.policy_store = Some(Arc::new(TenantSnapshotStore {
        default_bundle: None,
        bundles: vec![],
        full_snapshot_reads: full_snapshot_reads.clone(),
        full_snapshot_started: None,
        full_snapshot_release: None,
    }));
    *deps.last_tenant_policy_hash.lock().unwrap() = Some("stale".to_owned());

    assert_eq!(
        super::refresh_tenant_policy_engines(&deps).await.unwrap(),
        Some(0),
    );
    assert_eq!(engine.tenant_count(), 0);
    assert!(
        Arc::ptr_eq(&default, &engine.snapshot_for_tenant("acme")),
        "a tenant without a published bundle falls back to default",
    );
    assert_eq!(
        super::refresh_tenant_policy_engines(&deps).await.unwrap(),
        None,
        "an unchanged tenant snapshot does not rebuild Cedar",
    );
    assert_eq!(
        full_snapshot_reads.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "an unchanged poll reads only bundle signatures, not full Cedar source",
    );
}

#[tokio::test]
async fn tenant_refresh_coalesces_a_local_delete_doorbell_echo() {
    let dir = TmpDir::new();
    dir.write("10-default.cedar", "forbid(principal, action, resource);");
    let engine = Arc::new(ReloadableCedar::new(load_cedar_from_dir(&dir.0).unwrap()));
    let tenant_source = "permit(principal, action, resource);";
    engine.replace_tenants_with_fingerprints(HashMap::from([(
        "acme".to_owned(),
        (
            waygate_authz::CedarEngine::from_source(tenant_source).unwrap(),
            waygate_policy::content_hash(tenant_source),
        ),
    )]));

    let full_snapshot_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut deps = deps_with(&dir.0, engine.clone());
    deps.policy_store = Some(Arc::new(TenantSnapshotStore {
        default_bundle: None,
        bundles: vec![],
        full_snapshot_reads: full_snapshot_reads.clone(),
        full_snapshot_started: None,
        full_snapshot_release: None,
    }));
    *deps.last_tenant_policy_hash.lock().unwrap() = Some("pre-delete".to_owned());

    let epoch = deps.pool.tool_catalog_epoch();
    let change = epoch.begin_change();
    assert!(engine.remove_tenant("acme"));
    change.commit();
    assert_eq!(epoch.current(), 1, "the local delete emits the change");

    assert_eq!(
        super::refresh_tenant_policy_engines(&deps).await.unwrap(),
        None,
        "the returning doorbell recognizes the exact live post-delete policy set",
    );
    assert_eq!(
        epoch.current(),
        1,
        "the doorbell echo must not emit a duplicate catalog change",
    );
    assert_eq!(
        full_snapshot_reads.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "exact metadata fingerprints avoid recompiling an already-live set",
    );
}

#[tokio::test]
async fn tenant_refresh_restores_a_recreated_same_signature_bundle() {
    let dir = TmpDir::new();
    dir.write("10-default.cedar", "forbid(principal, action, resource);");
    let engine = Arc::new(ReloadableCedar::new(load_cedar_from_dir(&dir.0).unwrap()));
    let tenant_source = "permit(principal, action, resource);";
    engine.replace_tenants(HashMap::from([(
        "acme".to_owned(),
        waygate_authz::CedarEngine::from_source(tenant_source).unwrap(),
    )]));

    let full_snapshot_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let store: waygate_policy::SharedPolicyStore = Arc::new(TenantSnapshotStore {
        default_bundle: None,
        bundles: vec![tenant_bundle("acme", tenant_source)],
        full_snapshot_reads: full_snapshot_reads.clone(),
        full_snapshot_started: None,
        full_snapshot_release: None,
    });
    let loaded_signature = super::compile_tenant_policy_engines(Some(&store))
        .await
        .unwrap()
        .signature;
    assert!(engine.remove_tenant("acme"));

    let mut deps = deps_with(&dir.0, engine.clone());
    deps.policy_store = Some(store);
    *deps.last_tenant_policy_hash.lock().unwrap() = Some(loaded_signature);

    assert_eq!(
        super::refresh_tenant_policy_engines(&deps).await.unwrap(),
        Some(1),
        "matching durable hashes must not hide a locally missing tenant engine",
    );
    assert_eq!(engine.tenant_ids(), vec!["acme"]);
    assert_eq!(
        super::refresh_tenant_policy_engines(&deps).await.unwrap(),
        None,
    );
    assert_eq!(
        full_snapshot_reads.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "the restored registry returns to metadata-only polling",
    );
}

#[tokio::test]
async fn tenant_refresh_does_not_overwrite_a_concurrent_local_removal() {
    let dir = TmpDir::new();
    dir.write("10-default.cedar", "forbid(principal, action, resource);");
    let engine = Arc::new(ReloadableCedar::new(load_cedar_from_dir(&dir.0).unwrap()));
    engine.replace_tenants(HashMap::from([(
        "acme".to_owned(),
        waygate_authz::CedarEngine::from_source("permit(principal, action, resource);").unwrap(),
    )]));

    let full_snapshot_started = Arc::new(tokio::sync::Semaphore::new(0));
    let full_snapshot_release = Arc::new(tokio::sync::Semaphore::new(0));
    let mut deps = deps_with(&dir.0, engine.clone());
    deps.policy_store = Some(Arc::new(TenantSnapshotStore {
        default_bundle: None,
        bundles: vec![tenant_bundle(
            "acme",
            "forbid(principal, action, resource);",
        )],
        full_snapshot_reads: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        full_snapshot_started: Some(full_snapshot_started.clone()),
        full_snapshot_release: Some(full_snapshot_release.clone()),
    }));
    *deps.last_tenant_policy_hash.lock().unwrap() = Some("stale".to_owned());
    let deps = Arc::new(deps);
    let refresh = {
        let deps = deps.clone();
        tokio::spawn(async move { super::refresh_tenant_policy_engines(&deps).await })
    };

    full_snapshot_started
        .acquire()
        .await
        .expect("refresh reached full snapshot")
        .forget();
    assert!(engine.remove_tenant("acme"));
    full_snapshot_release.add_permits(1);

    assert_eq!(refresh.await.unwrap().unwrap(), None);
    assert!(
        engine.tenant_ids().is_empty(),
        "an older database snapshot must not resurrect a concurrently removed tenant engine",
    );
}

#[tokio::test]
async fn reloads_on_change_noops_when_unchanged_then_picks_up_a_later_change() {
    let dir = TmpDir::new();
    dir.write("10-a.cedar", "permit(principal, action, resource);");

    // Seed the engine on a DIFFERENT set than disk so the first reload must
    // swap (different content ⇒ different hash, even at equal policy count).
    let seed = TmpDir::new();
    seed.write("10-seed.cedar", "forbid(principal, action, resource);");
    let engine = Arc::new(ReloadableCedar::new(load_cedar_from_dir(&seed.0).unwrap()));
    let deps = deps_with(&dir.0, engine.clone());
    let epoch = deps.pool.tool_catalog_epoch();

    let snap0 = engine.snapshot();
    reload_policies_only(&deps).await;
    let snap1 = engine.snapshot();
    assert!(
        !Arc::ptr_eq(&snap0, &snap1),
        "a changed on-disk set must swap the live engine",
    );
    assert_eq!(snap1.list_policies().len(), 1, "engine now reflects disk");
    assert_eq!(
        epoch.current(),
        1,
        "a successful policy swap invalidates discovery"
    );

    // Second call, disk UNCHANGED: the change-detection gate must no-op — no
    // engine swap (same inner Arc), so no Cedar rebuild and no audit spam.
    reload_policies_only(&deps).await;
    let snap2 = engine.snapshot();
    assert!(
        Arc::ptr_eq(&snap1, &snap2),
        "an unchanged on-disk set must NOT swap the engine",
    );
    assert_eq!(epoch.current(), 1, "an unchanged policy tick stays quiet");

    // A later edit to policies/*.cedar must be picked up.
    dir.write("20-b.cedar", "forbid(principal, action, resource);");
    reload_policies_only(&deps).await;
    let snap3 = engine.snapshot();
    assert!(
        !Arc::ptr_eq(&snap2, &snap3),
        "a later on-disk change must swap the engine again",
    );
    assert_eq!(
        snap3.list_policies().len(),
        2,
        "the engine reflects the added policy",
    );
    assert_eq!(
        epoch.current(),
        2,
        "the later policy swap invalidates discovery"
    );
}

#[tokio::test]
async fn default_policy_swap_invalidates_before_best_effort_audit_finishes() {
    let dir = TmpDir::new();
    dir.write("10-a.cedar", "permit(principal, action, resource);");
    let seed = TmpDir::new();
    seed.write("10-seed.cedar", "forbid(principal, action, resource);");
    let engine = Arc::new(ReloadableCedar::new(load_cedar_from_dir(&seed.0).unwrap()));
    let audit = Arc::new(BlockingAudit::new());
    let mut deps = deps_with(&dir.0, engine.clone());
    deps.audit = audit.clone();
    let epoch = deps.pool.tool_catalog_epoch();
    let deps = Arc::new(deps);

    let reload = {
        let deps = deps.clone();
        tokio::spawn(async move { reload_policies_only(&deps).await })
    };
    audit
        .started
        .acquire()
        .await
        .expect("reload reached best-effort audit")
        .forget();

    assert_eq!(epoch.current(), 1, "the live swap invalidates discovery");
    assert_eq!(engine.snapshot().list_policies().len(), 1);
    assert!(
        !reload.is_finished(),
        "the audit remains blocked while invalidation is already visible"
    );

    audit.release.add_permits(1);
    reload.await.expect("reload task");
}

#[tokio::test]
async fn tenant_policy_swap_invalidates_before_best_effort_audit_finishes() {
    let missing = std::env::temp_dir().join(format!("poldoor-missing-{}", Uuid::now_v7()));
    let seed = TmpDir::new();
    seed.write("10-seed.cedar", "forbid(principal, action, resource);");
    let engine = Arc::new(ReloadableCedar::new(load_cedar_from_dir(&seed.0).unwrap()));
    let audit = Arc::new(BlockingAudit::new());
    let mut deps = deps_with(&missing, engine.clone());
    deps.audit = audit.clone();
    deps.policy_store = Some(Arc::new(TenantSnapshotStore {
        default_bundle: None,
        bundles: vec![tenant_bundle(
            "acme",
            "permit(principal, action, resource);",
        )],
        full_snapshot_reads: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        full_snapshot_started: None,
        full_snapshot_release: None,
    }));
    let epoch = deps.pool.tool_catalog_epoch();
    let deps = Arc::new(deps);

    let reload = {
        let deps = deps.clone();
        tokio::spawn(async move { reload_policies_only(&deps).await })
    };
    audit
        .started
        .acquire()
        .await
        .expect("reload reached best-effort audit")
        .forget();

    assert_eq!(epoch.current(), 1, "the live swap invalidates discovery");
    assert_eq!(engine.tenant_ids(), vec!["acme"]);
    assert!(
        !reload.is_finished(),
        "the audit remains blocked while invalidation is already visible"
    );

    audit.release.add_permits(1);
    reload.await.expect("reload task");
}

#[tokio::test]
async fn tenant_policy_swap_invalidates_when_default_source_is_unreadable() {
    let missing = std::env::temp_dir().join(format!("poldoor-missing-{}", Uuid::now_v7()));
    let seed = TmpDir::new();
    seed.write("10-seed.cedar", "forbid(principal, action, resource);");
    let engine = Arc::new(ReloadableCedar::new(load_cedar_from_dir(&seed.0).unwrap()));
    let mut deps = deps_with(&missing, engine.clone());
    deps.policy_store = Some(Arc::new(TenantSnapshotStore {
        default_bundle: None,
        bundles: vec![tenant_bundle(
            "acme",
            "permit(principal, action, resource);",
        )],
        full_snapshot_reads: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        full_snapshot_started: None,
        full_snapshot_release: None,
    }));

    reload_policies_only(&deps).await;

    assert_eq!(deps.pool.tool_catalog_epoch().current(), 1);
    assert_eq!(engine.tenant_ids(), vec!["acme"]);
}

#[tokio::test]
async fn unreadable_dir_keeps_the_previous_engine() {
    // A missing policies dir is fail-closed: keep the previous engine, never
    // panic or install an empty (deny-all) set.
    let seed = TmpDir::new();
    seed.write("10-seed.cedar", "permit(principal, action, resource);");
    let engine = Arc::new(ReloadableCedar::new(load_cedar_from_dir(&seed.0).unwrap()));
    let missing = std::env::temp_dir().join(format!("poldoor-missing-{}", Uuid::now_v7()));
    let deps = deps_with(&missing, engine.clone());
    let epoch = deps.pool.tool_catalog_epoch();
    deps.policy_config_health
        .set_healthy("was fine — pre-reload");

    let before = engine.snapshot();
    reload_policies_only(&deps).await;
    let after = engine.snapshot();
    assert!(
        Arc::ptr_eq(&before, &after),
        "an unreadable dir must keep the previous engine (no swap)",
    );
    assert_eq!(after.list_policies().len(), 1, "previous set still served");
    // A refused reload (unreadable dir) must ALSO surface the banner
    // degraded — the gate kept the previous set, but loudly.
    assert!(
        !deps
            .policy_config_health
            .snapshot()
            .expect("policy health set")
            .healthy,
        "an unreadable policies dir must mark policy config-health degraded",
    );
    assert_eq!(
        epoch.current(),
        0,
        "a refused reload must not invalidate discovery"
    );
}

#[tokio::test]
async fn rejected_policy_edit_does_not_replace_live_engine_with_recovery_bundle() {
    let dir = TmpDir::new();
    dir.write("10-broken.cedar", "this is not cedar");
    let seed = TmpDir::new();
    seed.write("10-live.cedar", "forbid(principal, action, resource);");
    let engine = Arc::new(ReloadableCedar::new(load_cedar_from_dir(&seed.0).unwrap()));
    let mut deps = deps_with(&dir.0, engine.clone());
    deps.policy_store = Some(Arc::new(TenantSnapshotStore {
        default_bundle: Some(tenant_bundle(
            waygate_core::TenantId::DEFAULT,
            "permit(principal, action, resource);",
        )),
        bundles: Vec::new(),
        full_snapshot_reads: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        full_snapshot_started: None,
        full_snapshot_release: None,
    }));
    let epoch = deps.pool.tool_catalog_epoch();
    super::refresh_tenant_policy_engines(&deps)
        .await
        .expect("converge the independent tenant-policy registry");
    let before_epoch = epoch.current();
    let before = engine.snapshot();

    reload_policies_only(&deps).await;

    assert!(
        Arc::ptr_eq(&before, &engine.snapshot()),
        "a rejected edit must preserve the actual in-memory last-known-good engine",
    );
    assert_eq!(
        epoch.current(),
        before_epoch,
        "a refused policy swap must not invalidate discovery"
    );
    assert!(
        !deps
            .policy_config_health
            .snapshot()
            .expect("policy health set")
            .healthy,
        "the rejected edit must remain operator-visible",
    );
}

#[tokio::test]
async fn clean_reload_marks_policy_config_health_healthy() {
    // A clean policy reload must flip the policy config-health signal
    // healthy, clearing any prior stale banner: a successful reload must
    // not leave the page degraded.
    let dir = TmpDir::new();
    dir.write("10-a.cedar", "permit(principal, action, resource);");
    // Seed the engine on a different set so the reload actually swaps + sets.
    let seed = TmpDir::new();
    seed.write("10-seed.cedar", "forbid(principal, action, resource);");
    let engine = Arc::new(ReloadableCedar::new(load_cedar_from_dir(&seed.0).unwrap()));
    let deps = deps_with(&dir.0, engine);
    deps.policy_config_health
        .set_degraded("was broken — pre-reload");

    reload_policies_only(&deps).await;

    assert!(
        deps.policy_config_health
            .snapshot()
            .expect("policy health set")
            .healthy,
        "a clean policy reload must mark policy config-health healthy",
    );
}

#[tokio::test]
async fn banner_clears_after_unreadable_blip_recovers_with_unchanged_bytes() {
    // A transient unreadable-dir tick leaves the banner degraded but
    // `last_policy_hash` at the good hash. When the dir returns with the
    // SAME bytes, the engine reload is a no-op (changed=false) — but the
    // banner must still CLEAR, because health reflects the current on-disk
    // set every tick, not only on a content change.
    let dir = TmpDir::new();
    dir.write("10-a.cedar", "permit(principal, action, resource);");
    let engine = Arc::new(ReloadableCedar::new(load_cedar_from_dir(&dir.0).unwrap()));
    let deps = deps_with(&dir.0, engine);

    // A first clean reload seeds last_policy_hash to disk's hash + sets healthy.
    reload_policies_only(&deps).await;
    assert!(deps.policy_config_health.snapshot().expect("set").healthy);

    // Simulate the degraded state a prior unreadable-dir tick left behind.
    deps.policy_config_health
        .set_degraded("transient unreadable blip");

    // Reload with UNCHANGED bytes: the engine swap is skipped (changed=false),
    // but the banner must clear because disk reads clean again.
    reload_policies_only(&deps).await;
    assert!(
        deps.policy_config_health.snapshot().expect("set").healthy,
        "a clean reload with unchanged bytes must clear a stale banner",
    );
}

/// Counts pointer reconciles by counting `seed_pointer` — which only
/// `reconcile_pointer` calls (for an absent pointer it seeds). `active_bundle`
/// → `NotFound`, so the boot/reload recorder now seeds the ledger AND runs the
/// in-flight guard (reading the pointer); counting `read_pointer` would
/// double-count that guard read, so we count `seed_pointer`, which the
/// recorder never calls — isolating the reconcile count.
struct ReconcileCountingStore {
    seed_pointer_calls: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait::async_trait]
impl waygate_policy::PolicyStore for ReconcileCountingStore {
    async fn active_bundle(
        &self,
        _t: &str,
    ) -> Result<waygate_policy::PolicyBundle, waygate_policy::PolicyError> {
        Err(waygate_policy::PolicyError::NotFound("no published bundle"))
    }
    async fn active_bundles(
        &self,
    ) -> Result<Vec<waygate_policy::PolicyBundle>, waygate_policy::PolicyError> {
        Ok(Vec::new())
    }
    async fn read_pointer(
        &self,
        _t: &str,
    ) -> Result<Option<waygate_policy::PolicyPointer>, waygate_policy::PolicyError> {
        Ok(None) // absent ⇒ reconcile seeds (a no-op CAS); not in-flight ⇒ seed proceeds
    }
    async fn seed_pointer(&self, _t: &str, _h: &str) -> Result<(), waygate_policy::PolicyError> {
        self.seed_pointer_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    async fn list_bundles(
        &self,
        _t: &str,
    ) -> Result<Vec<waygate_policy::PolicyBundleSummary>, waygate_policy::PolicyError> {
        unimplemented!()
    }
    async fn get(
        &self,
        _t: &str,
        _id: Uuid,
    ) -> Result<waygate_policy::PolicyBundle, waygate_policy::PolicyError> {
        unimplemented!()
    }
    async fn create_draft(
        &self,
        _t: &str,
        c: &str,
        _tests: Option<&serde_json::Value>,
        a: Option<&str>,
    ) -> Result<waygate_policy::PolicyBundle, waygate_policy::PolicyError> {
        // The recorder seeds when active_bundle is NotFound; return a minimal
        // draft. This fake doesn't persist (active_bundle stays NotFound), so
        // every tick re-seeds — harmless here: the test counts read_pointer,
        // which the seed path never calls.
        Ok(waygate_policy::PolicyBundle {
            id: Uuid::now_v7(),
            tenant_id: "default".into(),
            version: 1,
            status: waygate_policy::PolicyStatus::Draft,
            content: c.to_owned(),
            content_hash: waygate_policy::content_hash(c),
            tests: None,
            author: a.map(str::to_owned),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            published_at: None,
            published_by: None,
        })
    }
    async fn publish(
        &self,
        _t: &str,
        _id: Uuid,
        by: &str,
    ) -> Result<waygate_policy::PolicyBundle, waygate_policy::PolicyError> {
        let content = "permit(principal, action, resource);";
        Ok(waygate_policy::PolicyBundle {
            id: Uuid::now_v7(),
            tenant_id: "default".into(),
            version: 1,
            status: waygate_policy::PolicyStatus::Published,
            content: content.into(),
            content_hash: waygate_policy::content_hash(content),
            tests: None,
            author: None,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            published_at: Some(time::OffsetDateTime::UNIX_EPOCH),
            published_by: Some(by.to_owned()),
        })
    }
    async fn rollback_to(
        &self,
        _t: &str,
        _v: i32,
        _by: &str,
    ) -> Result<waygate_policy::PolicyBundle, waygate_policy::PolicyError> {
        unimplemented!()
    }
    async fn delete_all_bundles_for_tenant(
        &self,
        _t: &str,
    ) -> Result<u64, waygate_policy::PolicyError> {
        unimplemented!()
    }
    async fn cas_pointer(
        &self,
        _t: &str,
        _e: &str,
        _n: &str,
        _a: &str,
    ) -> Result<waygate_policy::TurnstileOutcome, waygate_policy::PolicyError> {
        unimplemented!()
    }
}

#[tokio::test]
async fn convergence_retries_on_an_unchanged_disk_tick() {
    // The pointer reconcile must run on EVERY clean tick, not only when the
    // on-disk hash changed — else a reconcile that failed/deferred on the
    // first tick is never retried for unchanged disk, leaving the pointer
    // stale and blocking later dashboard writes. Two reloads of an UNCHANGED
    // dir must reconcile twice (the engine swap stays gated on change).
    let dir = TmpDir::new();
    dir.write("10-a.cedar", "permit(principal, action, resource);");
    let engine = Arc::new(ReloadableCedar::new(load_cedar_from_dir(&dir.0).unwrap()));
    // Share the counter with the test so we can read it without downcasting
    // the trait object.
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let store: waygate_policy::SharedPolicyStore = Arc::new(ReconcileCountingStore {
        seed_pointer_calls: counter.clone(),
    });
    let mut deps = deps_with(&dir.0, engine);
    deps.policy_store = Some(store);

    // First tick: hash differs from the seed (None) ⇒ swap + converge.
    reload_policies_only(&deps).await;
    // Second tick: disk UNCHANGED ⇒ engine swap is skipped, but convergence
    // must still run (the fix). The counter proves the reconcile ran again.
    reload_policies_only(&deps).await;

    assert_eq!(
        counter.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "the pointer reconcile must run on both ticks, not just the changed one",
    );
}
