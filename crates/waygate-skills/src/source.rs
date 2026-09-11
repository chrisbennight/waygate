use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use thiserror::Error;

use crate::{
    CatalogValidationError, LoadedSkillResource, SkillCatalogSnapshot, SkillResourceDescriptor,
};

#[derive(Debug, Error)]
pub enum SkillResourceLoadError {
    #[error("skill resource is unavailable")]
    Unavailable(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("skill resource size changed: {0}")]
    SizeMismatch(String),
    #[error("skill resource identity changed: {0}")]
    IdentityMismatch(String),
    #[error("skill resource content digest changed: {0}")]
    DigestMismatch(String),
}

#[async_trait]
pub trait SkillResourceLoader: Send + Sync {
    async fn load(
        &self,
        descriptor: &SkillResourceDescriptor,
    ) -> Result<Vec<u8>, SkillResourceLoadError>;
}

#[derive(Debug, Clone, Default)]
pub struct InMemorySkillResourceLoader {
    resources: Arc<BTreeMap<String, Vec<u8>>>,
}

impl InMemorySkillResourceLoader {
    pub fn new(resources: BTreeMap<String, Vec<u8>>) -> Self {
        Self {
            resources: Arc::new(resources),
        }
    }
}

#[async_trait]
impl SkillResourceLoader for InMemorySkillResourceLoader {
    async fn load(
        &self,
        descriptor: &SkillResourceDescriptor,
    ) -> Result<Vec<u8>, SkillResourceLoadError> {
        self.resources.get(&descriptor.uri).cloned().ok_or_else(|| {
            SkillResourceLoadError::Unavailable(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "resource missing from in-memory source",
            )))
        })
    }
}

#[derive(Debug, Error)]
pub enum SkillSourceError {
    #[error("skill source has been withdrawn")]
    Withdrawn,
    #[error("skill source is unavailable")]
    Unavailable(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    Invalid(#[from] CatalogValidationError),
}

#[async_trait]
pub trait SkillCatalogSource: Send + Sync {
    /// Resolve and verify a complete immutable catalog snapshot.
    async fn load(&self) -> Result<SkillCatalogSnapshot, SkillSourceError>;

    /// Restore an immutable revision within this source's configured boundary.
    /// Sources without historical access refuse rather than substitute current bytes.
    async fn restore(
        &self,
        _identity: &crate::CatalogSourceIdentity,
    ) -> Result<SkillCatalogSnapshot, SkillSourceError> {
        Err(SkillSourceError::Unavailable(Box::new(
            std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "source does not support immutable revision restoration",
            ),
        )))
    }
}

/// Atomically published last-known-good skill catalog.
///
/// Source I/O and validation finish before the write lock is taken. A failed
/// refresh returns its error and cannot replace the snapshot readers already
/// trust.
#[derive(Debug, Default)]
struct CatalogState {
    current: Option<Arc<SkillCatalogSnapshot>>,
    previous: VecDeque<Arc<SkillCatalogSnapshot>>,
    withdrawn: bool,
    latest_refresh_failed: bool,
    failed_resource_reads: BTreeSet<String>,
}

#[derive(Debug, Default)]
pub struct ReloadableSkillCatalog {
    state: RwLock<CatalogState>,
}

#[derive(Debug, Clone)]
pub struct SkillCatalogStatus {
    pub snapshot: Option<Arc<SkillCatalogSnapshot>>,
    pub latest_refresh_failed: bool,
    pub resource_read_failed: bool,
}

impl ReloadableSkillCatalog {
    pub fn at_source(
        &self,
        source: &crate::CatalogSourceIdentity,
    ) -> Option<Arc<SkillCatalogSnapshot>> {
        let state = self.state.read().expect("skill catalog lock poisoned");
        state
            .current
            .iter()
            .chain(state.previous.iter())
            .find(|snapshot| snapshot.source() == source)
            .cloned()
    }

    /// Retain verified historical metadata without publishing it as the current
    /// source. Withdrawal or a configured-source change during acquisition wins.
    pub fn retain_restored(&self, snapshot: Arc<SkillCatalogSnapshot>) -> bool {
        let mut state = self.state.write().expect("skill catalog lock poisoned");
        let Some(current) = state.current.as_ref() else {
            return false;
        };
        if state.withdrawn
            || current.source().origin != snapshot.source().origin
            || current.source().reference != snapshot.source().reference
        {
            return false;
        }
        if current.revision() != snapshot.revision() {
            state
                .previous
                .retain(|entry| entry.revision() != snapshot.revision());
            state.previous.push_front(snapshot);
            state.previous.truncate(4);
        }
        true
    }

    pub fn current(&self) -> Option<Arc<SkillCatalogSnapshot>> {
        self.state
            .read()
            .expect("skill catalog lock poisoned")
            .current
            .clone()
    }

    /// Resolve a catalog revision without substituting newer workflow content.
    /// Retention is bounded to the current and four previous distinct snapshots.
    /// A restart, eviction, or withdrawal requires callers to load a new workflow.
    pub fn at_revision(&self, revision: &str) -> Option<Arc<SkillCatalogSnapshot>> {
        let state = self.state.read().expect("skill catalog lock poisoned");
        state
            .current
            .iter()
            .chain(state.previous.iter())
            .find(|snapshot| snapshot.revision() == revision)
            .cloned()
    }

    pub fn status(&self) -> SkillCatalogStatus {
        let state = self.state.read().expect("skill catalog lock poisoned");
        SkillCatalogStatus {
            snapshot: state.current.clone(),
            latest_refresh_failed: state.latest_refresh_failed,
            resource_read_failed: !state.failed_resource_reads.is_empty(),
        }
    }

    /// Load one resource and retain health evidence for the active generation.
    ///
    /// A read completing against an older immutable snapshot cannot change the
    /// health of a replacement published while its source I/O was in flight.
    pub async fn load_resource(
        &self,
        snapshot: &Arc<SkillCatalogSnapshot>,
        uri: &str,
    ) -> Result<Option<LoadedSkillResource>, SkillResourceLoadError> {
        let result = snapshot.load_resource(uri).await;
        let mut state = self.state.write().expect("skill catalog lock poisoned");
        let still_current = state
            .current
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, snapshot));
        if !state.withdrawn && still_current {
            match &result {
                Ok(Some(_)) => {
                    state.failed_resource_reads.remove(uri);
                }
                Ok(None) => {}
                Err(_) => {
                    state.failed_resource_reads.insert(uri.to_owned());
                }
            }
        }
        result
    }

    pub async fn refresh(
        &self,
        source: &dyn SkillCatalogSource,
    ) -> Result<Arc<SkillCatalogSnapshot>, SkillSourceError> {
        if self
            .state
            .read()
            .expect("skill catalog lock poisoned")
            .withdrawn
        {
            return Err(SkillSourceError::Withdrawn);
        }
        let loaded = source.load().await;
        let mut state = self.state.write().expect("skill catalog lock poisoned");
        if state.withdrawn {
            return Err(SkillSourceError::Withdrawn);
        }
        match loaded {
            Ok(snapshot) => {
                let fresh = Arc::new(snapshot);
                if let Some(previous) = state.current.take() {
                    if previous.revision() != fresh.revision() {
                        state
                            .previous
                            .retain(|entry| entry.revision() != fresh.revision());
                        state.previous.push_front(previous);
                        state.previous.truncate(4);
                    }
                }
                state.current = Some(fresh.clone());
                state.latest_refresh_failed = false;
                state.failed_resource_reads.clear();
                Ok(fresh)
            }
            Err(error) => {
                state.latest_refresh_failed = true;
                Err(error)
            }
        }
    }

    /// Record a refresh failure detected by the caller, such as a timeout
    /// that cancelled the source future before it could return an error.
    pub fn mark_refresh_failed(&self) {
        let mut state = self.state.write().expect("skill catalog lock poisoned");
        if !state.withdrawn {
            state.latest_refresh_failed = true;
        }
    }

    /// Stop publishing the source for new requests.
    ///
    /// Existing readers that already cloned the immutable snapshot may finish,
    /// while later reads observe no catalog. This preserves historical
    /// evidence without letting a removed or revoked source authorize new use.
    pub fn withdraw(&self) -> Option<Arc<SkillCatalogSnapshot>> {
        let mut state = self.state.write().expect("skill catalog lock poisoned");
        state.withdrawn = true;
        state.previous.clear();
        state.failed_resource_reads.clear();
        state.current.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        verify_catalog_snapshot, CatalogManifest, CatalogSkill, CatalogSourceIdentity,
        SkillResourceDescriptor, CATALOG_SCHEMA_VERSION,
    };
    use serde_json::{Map, Value};
    use std::{
        collections::BTreeMap,
        io,
        sync::atomic::{AtomicBool, Ordering},
    };
    use tokio::sync::Notify;

    struct StaticSource(Result<SkillCatalogSnapshot, &'static str>);

    struct BlockingSource {
        started: Notify,
        release: Notify,
        snapshot: SkillCatalogSnapshot,
    }

    struct ToggleLoader {
        fail: AtomicBool,
        bytes: Vec<u8>,
    }

    #[async_trait]
    impl SkillResourceLoader for ToggleLoader {
        async fn load(
            &self,
            _descriptor: &SkillResourceDescriptor,
        ) -> Result<Vec<u8>, SkillResourceLoadError> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(SkillResourceLoadError::Unavailable(Box::new(
                    io::Error::other("resource unavailable"),
                )));
            }
            Ok(self.bytes.clone())
        }
    }

    #[async_trait]
    impl SkillCatalogSource for StaticSource {
        async fn load(&self) -> Result<SkillCatalogSnapshot, SkillSourceError> {
            match &self.0 {
                Ok(snapshot) => Ok(snapshot.clone()),
                Err(message) => Err(SkillSourceError::Unavailable(Box::new(io::Error::other(
                    *message,
                )))),
            }
        }
    }

    #[async_trait]
    impl SkillCatalogSource for BlockingSource {
        async fn load(&self) -> Result<SkillCatalogSnapshot, SkillSourceError> {
            self.started.notify_one();
            self.release.notified().await;
            Ok(self.snapshot.clone())
        }
    }

    fn snapshot_with_loader(
        origin: &str,
        loader: Arc<dyn SkillResourceLoader>,
    ) -> SkillCatalogSnapshot {
        let skill_md = b"---\nname: demo\ndescription: Demo skill\n---\n# Demo\n";
        let digest = crate::validate::sha256_digest(skill_md);
        let mut frontmatter = Map::new();
        frontmatter.insert("name".into(), Value::String("demo".into()));
        frontmatter.insert("description".into(), Value::String("Demo skill".into()));
        let uri = "skill://demo/SKILL.md".to_owned();
        let resource = SkillResourceDescriptor {
            uri: uri.clone(),
            source_path: "demo/SKILL.md".into(),
            source_object: digest.clone(),
            size: skill_md.len() as u64,
            media_type: "text/markdown".into(),
        };
        verify_catalog_snapshot(
            CatalogSourceIdentity {
                origin: origin.into(),
                reference: "main".into(),
                resolved_digest: format!("git-sha1:{}", "a".repeat(40)),
                resolved_tree_digest: format!("git-sha1:{}", "b".repeat(40)),
            },
            CatalogManifest {
                schema_version: CATALOG_SCHEMA_VERSION,
                skills: vec![CatalogSkill {
                    uri: uri.clone(),
                    frontmatter,
                    resources: vec![resource],
                }],
            },
            BTreeMap::from([(uri, skill_md.to_vec())]),
            loader,
        )
        .expect("valid fixture")
    }

    fn snapshot(origin: &str) -> SkillCatalogSnapshot {
        let uri = "skill://demo/SKILL.md".to_owned();
        let bytes = b"---\nname: demo\ndescription: Demo skill\n---\n# Demo\n".to_vec();
        snapshot_with_loader(
            origin,
            Arc::new(InMemorySkillResourceLoader::new(BTreeMap::from([(
                uri, bytes,
            )]))),
        )
    }

    #[tokio::test]
    async fn revisions_survive_refresh_without_unbounded_retention() {
        let catalog = ReloadableSkillCatalog::default();
        let original = catalog
            .refresh(&StaticSource(Ok(snapshot("original"))))
            .await
            .unwrap();
        let revision = original.revision();
        for _ in 0..8 {
            catalog
                .refresh(&StaticSource(Ok(snapshot("same"))))
                .await
                .unwrap();
        }
        assert_eq!(
            catalog.at_revision(&revision).unwrap().source().origin,
            "original"
        );
        for name in ["two", "three", "four", "five"] {
            catalog
                .refresh(&StaticSource(Ok(snapshot(name))))
                .await
                .unwrap();
        }
        assert!(catalog.at_revision(&revision).is_none());
        let current = catalog.current().unwrap().revision();
        catalog.withdraw();
        assert!(catalog.at_revision(&current).is_none());
    }

    #[tokio::test]
    async fn failed_refresh_keeps_previous_snapshot() {
        let catalog = ReloadableSkillCatalog::default();
        catalog
            .refresh(&StaticSource(Ok(snapshot("initial"))))
            .await
            .expect("first refresh");

        let error = catalog
            .refresh(&StaticSource(Err("Git source unavailable")))
            .await
            .expect_err("refresh must fail");

        assert!(matches!(error, SkillSourceError::Unavailable(_)));
        let status = catalog.status();
        assert!(status.snapshot.is_some());
        assert!(status.latest_refresh_failed);
        assert_eq!(
            catalog
                .current()
                .expect("old snapshot remains")
                .source()
                .origin,
            "initial"
        );

        catalog
            .refresh(&StaticSource(Ok(snapshot("recovered"))))
            .await
            .expect("recovery refresh");
        assert!(!catalog.status().latest_refresh_failed);
    }

    #[tokio::test]
    async fn resource_failures_degrade_only_the_active_snapshot() {
        let loader = Arc::new(ToggleLoader {
            fail: AtomicBool::new(true),
            bytes: b"---\nname: demo\ndescription: Demo skill\n---\n# Demo\n".to_vec(),
        });
        let catalog = ReloadableSkillCatalog::default();
        catalog
            .refresh(&StaticSource(Ok(snapshot_with_loader(
                "initial",
                loader.clone(),
            ))))
            .await
            .expect("first refresh");
        let initial = catalog.current().expect("published snapshot");
        let uri = "skill://demo/SKILL.md";

        assert!(catalog.load_resource(&initial, uri).await.is_err());
        assert!(catalog.status().resource_read_failed);

        loader.fail.store(false, Ordering::SeqCst);
        catalog
            .load_resource(&initial, uri)
            .await
            .expect("recovered resource read");
        assert!(!catalog.status().resource_read_failed);

        catalog
            .refresh(&StaticSource(Ok(snapshot("replacement"))))
            .await
            .expect("replacement refresh");
        loader.fail.store(true, Ordering::SeqCst);
        assert!(catalog.load_resource(&initial, uri).await.is_err());
        assert!(!catalog.status().resource_read_failed);
    }

    #[tokio::test]
    async fn withdrawn_source_is_unavailable_to_new_readers() {
        let catalog = ReloadableSkillCatalog::default();
        catalog
            .refresh(&StaticSource(Ok(snapshot("initial"))))
            .await
            .expect("first refresh");

        let in_flight = catalog.current().expect("published snapshot");
        let withdrawn = catalog.withdraw().expect("withdrawn snapshot");

        assert!(catalog.current().is_none());
        assert_eq!(in_flight.source(), withdrawn.source());
    }

    #[tokio::test]
    async fn withdrawal_fences_in_flight_and_later_refreshes() {
        let catalog = Arc::new(ReloadableSkillCatalog::default());
        catalog
            .refresh(&StaticSource(Ok(snapshot("initial"))))
            .await
            .expect("first refresh");
        let source = Arc::new(BlockingSource {
            started: Notify::new(),
            release: Notify::new(),
            snapshot: snapshot("replacement"),
        });

        let pending = tokio::spawn({
            let catalog = catalog.clone();
            let source = source.clone();
            async move { catalog.refresh(source.as_ref()).await }
        });
        source.started.notified().await;

        catalog.withdraw().expect("published snapshot");
        source.release.notify_one();

        assert!(matches!(
            pending.await.expect("refresh task"),
            Err(SkillSourceError::Withdrawn)
        ));
        assert!(matches!(
            catalog.refresh(&StaticSource(Ok(snapshot("later")))).await,
            Err(SkillSourceError::Withdrawn)
        ));
        assert!(catalog.current().is_none());
    }
}
