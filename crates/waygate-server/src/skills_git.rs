use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
    time::Duration,
};

use anyhow::Context as _;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::{header, StatusCode};
use serde::{de::DeserializeOwned, Deserialize};
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use thiserror::Error;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use url::Url;
use waygate_core::http_client::{self, read_body_capped};
use waygate_skills::distribution::ReviewedSkillCatalog;
use waygate_skills::review::{PgSkillReviewStore, ReviewCandidate, ReviewError, SkillReviewStore};
use waygate_skills::{
    parse_skill_frontmatter, valid_skill_name, verify_catalog_snapshot, CatalogManifest,
    CatalogSkill, CatalogSourceIdentity, ReloadableSkillCatalog, SkillCatalogSnapshot,
    SkillCatalogSource, SkillResourceDescriptor, SkillResourceLoadError, SkillResourceLoader,
    SkillSourceError, CATALOG_SCHEMA_VERSION, MAX_SKILL_TOTAL_BYTES,
};
use waygate_tenants::TenantStore;

const METADATA_RESPONSE_LIMIT: usize = 8 * 1024 * 1024;
const BLOB_RESPONSE_LIMIT: usize = 24 * 1024 * 1024;
const MAX_TREE_ENTRIES: usize = 20_000;
const MAX_TREE_DEPTH: usize = 64;
const MAX_GIT_PATH_SEGMENT_BYTES: usize = 1_024;
const MAX_GIT_PATH_BYTES: usize = 4_096;
const MAX_CATALOG_PATH_BYTES: usize = 8 * 1024 * 1024;
const MAX_CATALOG_SKILLS: usize = 1_024;
const MAX_CATALOG_SKILL_METADATA_BYTES: u64 = MAX_SKILL_TOTAL_BYTES;
const TREE_PAGE_SIZE: usize = 1_000;
const MAX_TREE_PAGES: usize = 100;
// Decoding a specification-maximum resource holds both its base64 text and
// decoded bytes. Keep that transient memory and source egress process-bounded
// while still allowing independent discovery and resource work to overlap.
const MAX_CONCURRENT_GIT_BLOB_LOADS: usize = 2;
pub const DEFAULT_GIT_SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct SkillsGitConfig {
    pub api_url: Url,
    pub repository: String,
    pub reference: String,
    pub expected_commit: Option<String>,
    pub expected_tree: Option<String>,
    pub source_id: String,
    pub roots: Vec<String>,
    pub token_env: Option<String>,
    pub refresh_interval: Option<Duration>,
    pub snapshot_timeout: Duration,
}

/// Configured Git-backed skill discovery retained for the server lifetime.
pub struct ConfiguredSkills {
    runtime: Option<SkillsRuntime>,
    _refresh_task: Option<tokio::task::JoinHandle<()>>,
}

impl ConfiguredSkills {
    pub fn build(
        config: Option<&SkillsGitConfig>,
        shutdown: CancellationToken,
        catalog_epoch: waygate_mcp::ToolCatalogEpoch,
        database: Option<sqlx::PgPool>,
    ) -> anyhow::Result<Self> {
        let runtime = config
            .map(|config| SkillsRuntime::build(config, database))
            .transpose()?;
        let refresh_task = runtime
            .as_ref()
            .map(|runtime| runtime.spawn_refresh(shutdown, catalog_epoch));
        Ok(Self {
            runtime,
            _refresh_task: refresh_task,
        })
    }

    pub fn reviewed(&self) -> Option<Arc<ReviewedSkillCatalog>> {
        self.runtime
            .as_ref()
            .map(|runtime| runtime.reviewed.clone())
    }

    pub fn catalog(&self) -> Option<Arc<ReloadableSkillCatalog>> {
        self.runtime.as_ref().map(|runtime| runtime.catalog.clone())
    }
}

pub fn configure(
    config: &crate::config::Config,
    shutdown: &CancellationToken,
    catalog_epoch: &waygate_mcp::ToolCatalogEpoch,
    database: &Option<sqlx::PgPool>,
) -> anyhow::Result<ConfiguredSkills> {
    ConfiguredSkills::build(
        config.skills.as_ref(),
        shutdown.clone(),
        catalog_epoch.clone(),
        database.clone(),
    )
}

struct SkillsRuntime {
    catalog: Arc<ReloadableSkillCatalog>,
    source: Arc<ObservedSkillSource>,
    reviewed: Arc<ReviewedSkillCatalog>,
    refresh_interval: Option<Duration>,
    snapshot_timeout: Duration,
}

impl SkillsRuntime {
    fn build(config: &SkillsGitConfig, database: Option<sqlx::PgPool>) -> anyhow::Result<Self> {
        let http = http_client::builder(http_client::Profile::Slow)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("building the skill Git HTTP client")?;
        let source = Arc::new(
            GitSkillSource::new(http, config.clone())
                .context("validating the configured skill Git source")?,
        );
        let catalog = Arc::new(ReloadableSkillCatalog::default());
        let reviews = database
            .clone()
            .map(|pool| Arc::new(PgSkillReviewStore::new(pool)) as Arc<dyn SkillReviewStore>);
        let source = Arc::new(ObservedSkillSource {
            source,
            reviews: reviews.clone(),
            tenants: database.map(waygate_tenants::PgTenantStore::new),
        });
        let reviewed = Arc::new(ReviewedSkillCatalog::new(
            catalog.clone(),
            source.clone(),
            reviews,
        ));
        Ok(Self {
            catalog,
            source,
            reviewed,
            refresh_interval: config.refresh_interval,
            snapshot_timeout: config.snapshot_timeout,
        })
    }

    fn spawn_refresh(
        &self,
        shutdown: CancellationToken,
        catalog_epoch: waygate_mcp::ToolCatalogEpoch,
    ) -> tokio::task::JoinHandle<()> {
        let catalog = self.catalog.clone();
        let source = self.source.clone();
        let refresh_interval = self.refresh_interval;
        let snapshot_timeout = self.snapshot_timeout;
        tokio::spawn(async move {
            loop {
                let previous = catalog.current().map(|snapshot| snapshot.revision());
                refresh_once(&catalog, source.as_ref(), snapshot_timeout).await;
                if previous != catalog.current().map(|snapshot| snapshot.revision()) {
                    catalog_epoch.mark_changed();
                }
                let Some(interval) = refresh_interval else {
                    return;
                };
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tokio::time::sleep(interval) => {}
                }
            }
        })
    }
}

/// Capture review generations before Git acquisition so a slow refresh cannot
/// replace a candidate that an operator reviewed while that acquisition ran.
struct ObservedSkillSource {
    source: Arc<GitSkillSource>,
    reviews: Option<Arc<dyn SkillReviewStore>>,
    tenants: Option<waygate_tenants::PgTenantStore>,
}

#[async_trait]
impl SkillCatalogSource for ObservedSkillSource {
    async fn load(&self) -> Result<SkillCatalogSnapshot, SkillSourceError> {
        let (Some(reviews), Some(tenants)) = (&self.reviews, &self.tenants) else {
            return self.source.load().await;
        };
        let tenants = tenants
            .list()
            .await
            .map_err(|error| SkillSourceError::Unavailable(Box::new(error)))?;
        let origin = format!(
            "git+{}/{}",
            self.source.config.api_url.as_str().trim_end_matches('/'),
            self.source.config.repository
        );
        let reference = format!(
            "{}@{}",
            self.source.config.repository, self.source.config.reference
        );
        let source_key = ReviewCandidate::source_key_for(&origin, &reference);
        let mut generations = BTreeMap::new();
        for tenant in &tenants {
            let mut after = String::new();
            loop {
                let page = reviews
                    .list(&tenant.id, &source_key, &after, 200)
                    .await
                    .map_err(|error| SkillSourceError::Unavailable(Box::new(error)))?;
                if page.is_empty() {
                    break;
                }
                for review in page {
                    after = review.skill_uri.clone();
                    generations.insert((tenant.id.clone(), review.skill_uri), review.generation);
                }
            }
        }
        let snapshot = self.source.load().await?;
        for tenant in tenants {
            for skill in snapshot.skills() {
                let candidate = ReviewCandidate::from_snapshot(&snapshot, &skill.uri)
                    .expect("verified snapshot contains its skill");
                let generation = generations
                    .get(&(tenant.id.clone(), skill.uri.clone()))
                    .copied();
                match reviews.observe(&tenant.id, generation, &candidate).await {
                    Ok(_) | Err(ReviewError::Stale) => {}
                    Err(error) => return Err(SkillSourceError::Unavailable(Box::new(error))),
                }
            }
        }
        Ok(snapshot)
    }

    async fn restore(
        &self,
        identity: &CatalogSourceIdentity,
    ) -> Result<SkillCatalogSnapshot, SkillSourceError> {
        self.source.restore(identity).await
    }
}

async fn refresh_once(
    catalog: &ReloadableSkillCatalog,
    source: &dyn SkillCatalogSource,
    snapshot_timeout: Duration,
) {
    match tokio::time::timeout(snapshot_timeout, catalog.refresh(source)).await {
        Ok(Ok(snapshot)) => tracing::info!(
            source_revision = %snapshot.source().resolved_digest,
            skills = snapshot.skills().len(),
            "refreshed skill metadata from Git"
        ),
        Ok(Err(error)) => tracing::warn!(
            error = %error,
            "skill Git refresh failed; keeping the previous metadata snapshot"
        ),
        Err(_) => {
            catalog.mark_refresh_failed();
            tracing::warn!(
                "skill Git refresh exceeded its deadline; keeping the previous metadata snapshot"
            );
        }
    }
}

#[derive(Debug, Error)]
enum GitSourceError {
    #[error("skill Git source configuration is invalid")]
    InvalidSource,
    #[error("skill Git request failed")]
    Request(#[source] reqwest::Error),
    #[error("skill Git source returned HTTP {0}")]
    HttpStatus(StatusCode),
    #[error("skill Git response exceeded its byte limit")]
    ResponseTooLarge,
    #[error("skill Git response is invalid")]
    InvalidResponse(#[source] serde_json::Error),
    #[error("skill Git object id is invalid")]
    InvalidObjectId,
    #[error("skill Git token is unavailable")]
    CredentialUnavailable,
    #[error("skill Git tree exceeds the supported metadata boundary")]
    TreeTooLarge,
    #[error("skill Git catalog exceeds the supported skill metadata boundary")]
    CatalogTooLarge,
    #[error("skill Git tree contains an unsupported entry")]
    UnsupportedTreeEntry,
    #[error("configured skill tree does not match the resolved Git tree")]
    TreeMismatch,
    #[error("configured skill commit does not match the resolved Git revision")]
    CommitMismatch,
    #[error("skill Git object content does not match its object id")]
    ObjectMismatch,
    #[error("skill Git blob capacity is exhausted")]
    CapacityExhausted,
    #[error("skill metadata is invalid")]
    InvalidSkillMetadata,
    #[error(transparent)]
    Catalog(#[from] waygate_skills::CatalogValidationError),
}

#[derive(Clone)]
pub struct GitSkillSource {
    http: reqwest::Client,
    config: SkillsGitConfig,
    blob_capacity: Arc<Semaphore>,
}

impl fmt::Debug for GitSkillSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitSkillSource")
            .field("api_url", &self.config.api_url)
            .field("repository", &self.config.repository)
            .field("reference", &self.config.reference)
            .field("expected_commit", &self.config.expected_commit)
            .field("expected_tree", &self.config.expected_tree)
            .field("source_id", &self.config.source_id)
            .field("roots", &self.config.roots)
            .field("token_env", &self.config.token_env)
            .finish()
    }
}

impl GitSkillSource {
    fn new(http: reqwest::Client, config: SkillsGitConfig) -> Result<Self, GitSourceError> {
        if !valid_api_url(&config.api_url)
            || !valid_repository(&config.repository)
            || config.reference.trim().is_empty()
            || !valid_source_id(&config.source_id)
            || config.roots.is_empty()
            || config.roots.iter().any(|root| !valid_root(root))
            || config
                .expected_commit
                .as_deref()
                .is_some_and(|commit| git_digest(commit).is_none())
            || config
                .expected_tree
                .as_deref()
                .is_some_and(|tree| git_digest(tree).is_none())
            || roots_overlap(&config.roots)
        {
            return Err(GitSourceError::InvalidSource);
        }
        Ok(Self {
            http,
            config,
            blob_capacity: Arc::new(Semaphore::new(MAX_CONCURRENT_GIT_BLOB_LOADS)),
        })
    }

    async fn load_snapshot(&self) -> Result<SkillCatalogSnapshot, GitSourceError> {
        self.load_snapshot_at(
            &self.config.reference,
            self.config.expected_commit.as_deref(),
            self.config.expected_tree.as_deref(),
        )
        .await
    }

    async fn load_snapshot_at(
        &self,
        reference: &str,
        expected_commit: Option<&str>,
        expected_tree: Option<&str>,
    ) -> Result<SkillCatalogSnapshot, GitSourceError> {
        let commit: CommitResponse = self
            .get_json(
                self.endpoint(&[
                    "repos",
                    self.owner(),
                    self.repo(),
                    "git",
                    "commits",
                    reference,
                ])?,
                METADATA_RESPONSE_LIMIT,
            )
            .await?;
        let revision = git_digest(&commit.sha).ok_or(GitSourceError::InvalidObjectId)?;
        if expected_commit.is_some_and(|expected| expected != commit.sha) {
            return Err(GitSourceError::CommitMismatch);
        }
        let top_tree = self.load_commit_tree_object(&commit.sha).await?;
        if expected_tree.is_some_and(|expected| expected != top_tree.id) {
            return Err(GitSourceError::TreeMismatch);
        }
        let tree = self.load_tree(&top_tree.entries).await?;
        let skill_roots = tree
            .iter()
            .filter(|entry| {
                entry.path.ends_with("/SKILL.md") && self.in_configured_root(&entry.path)
            })
            .map(|entry| entry.path.trim_end_matches("/SKILL.md").to_owned())
            .collect::<Vec<_>>();
        validate_catalog_metadata_budget(&tree, &skill_roots)?;
        let mut skills = Vec::with_capacity(skill_roots.len());
        let mut skill_markdown = BTreeMap::new();
        let mut remote_resources = BTreeMap::new();
        let mut loaded_skill_metadata_bytes = 0_u64;

        for skill_root in skill_roots {
            let root_entry = tree
                .iter()
                .find(|entry| entry.path == format!("{skill_root}/SKILL.md"))
                .expect("skill root came from the tree");
            let root_bytes = self.load_blob(root_entry).await?;
            loaded_skill_metadata_bytes = loaded_skill_metadata_bytes
                .checked_add(root_bytes.len() as u64)
                .filter(|total| *total <= MAX_CATALOG_SKILL_METADATA_BYTES)
                .ok_or(GitSourceError::CatalogTooLarge)?;
            let frontmatter = parse_skill_frontmatter(&root_bytes)
                .map_err(|_| GitSourceError::InvalidSkillMetadata)?;
            let name = validated_skill_name(&frontmatter)?;
            let skill_uri = format!("skill://{}/{name}/SKILL.md", self.config.source_id);
            let prefix = format!("{skill_root}/");
            let nested_roots = tree.iter().any(|entry| {
                entry.path != root_entry.path
                    && entry.path.starts_with(&prefix)
                    && entry.path.ends_with("/SKILL.md")
            });
            if nested_roots {
                return Err(GitSourceError::InvalidSkillMetadata);
            }
            let mut resources = Vec::new();
            for entry in tree.iter().filter(|entry| entry.path.starts_with(&prefix)) {
                if entry.kind == "tree" {
                    continue;
                }
                if entry.kind != "blob" || entry.mode != "100644" && entry.mode != "100755" {
                    return Err(GitSourceError::UnsupportedTreeEntry);
                }
                let relative = entry.path.strip_prefix(&prefix).expect("prefix checked");
                if relative.is_empty() || relative.split('/').any(invalid_segment) {
                    return Err(GitSourceError::UnsupportedTreeEntry);
                }
                let uri = format!("skill://{}/{name}/{relative}", self.config.source_id);
                let descriptor = SkillResourceDescriptor {
                    uri: uri.clone(),
                    source_path: entry.path.clone(),
                    source_object: git_digest(&entry.sha)
                        .ok_or(GitSourceError::UnsupportedTreeEntry)?,
                    size: entry.size.ok_or(GitSourceError::UnsupportedTreeEntry)?,
                    media_type: media_type(relative).to_owned(),
                };
                remote_resources.insert(
                    uri.clone(),
                    RemoteResource {
                        descriptor: descriptor.clone(),
                        path: entry.path.clone(),
                        sha: entry.sha.clone(),
                    },
                );
                resources.push(descriptor);
            }
            skill_markdown.insert(skill_uri.clone(), root_bytes);
            skills.push(CatalogSkill {
                uri: skill_uri,
                frontmatter,
                resources,
            });
        }

        let loader = Arc::new(GitResourceLoader {
            source: self.clone(),
            resources: Arc::new(remote_resources),
        });
        Ok(verify_catalog_snapshot(
            CatalogSourceIdentity {
                origin: format!(
                    "git+{}/{}",
                    self.config.api_url.as_str().trim_end_matches('/'),
                    self.config.repository
                ),
                reference: format!("{}@{}", self.config.repository, self.config.reference),
                resolved_digest: revision,
                resolved_tree_digest: git_digest(&top_tree.id)
                    .expect("verified tree has a supported Git object id"),
            },
            CatalogManifest {
                schema_version: CATALOG_SCHEMA_VERSION,
                skills,
            },
            skill_markdown,
            loader,
        )?)
    }

    async fn load_tree(&self, top_tree: &[TreeEntry]) -> Result<Vec<TreeEntry>, GitSourceError> {
        let mut entries = BTreeMap::new();
        let mut budget = TreePathBudget::default();
        for root in &self.config.roots {
            let root_entries = self.resolve_tree(top_tree, root).await?;
            let root_depth = root.split('/').count();
            let mut pending = Vec::new();
            index_tree_entries(
                root,
                root_depth,
                root_entries,
                &mut budget,
                &mut entries,
                &mut pending,
            )?;
            while let Some((prefix, parent_depth, tree_id)) = pending.pop() {
                let children = self.load_tree_object(&tree_id, Some(&tree_id)).await?;
                index_tree_entries(
                    &prefix,
                    parent_depth,
                    children.entries,
                    &mut budget,
                    &mut entries,
                    &mut pending,
                )?;
            }
        }
        Ok(entries.into_values().collect())
    }

    async fn resolve_tree(
        &self,
        top_tree: &[TreeEntry],
        root: &str,
    ) -> Result<Vec<TreeEntry>, GitSourceError> {
        let mut entries = top_tree.to_vec();
        for segment in root.split('/') {
            let entry = entries
                .iter()
                .find(|entry| entry.path == segment && entry.kind == "tree")
                .ok_or(GitSourceError::InvalidSkillMetadata)?;
            entries = self
                .load_tree_object(&entry.sha, Some(&entry.sha))
                .await?
                .entries;
        }
        Ok(entries)
    }

    async fn load_tree_object(
        &self,
        treeish: &str,
        expected: Option<&str>,
    ) -> Result<VerifiedTree, GitSourceError> {
        git_digest(treeish).ok_or(GitSourceError::InvalidObjectId)?;
        self.load_treeish_object(treeish, treeish.len(), expected)
            .await
    }

    async fn load_commit_tree_object(&self, commit: &str) -> Result<VerifiedTree, GitSourceError> {
        git_digest(commit).ok_or(GitSourceError::InvalidObjectId)?;
        // Gitea may echo a commit ID when its tree endpoint receives a bare
        // commit. Dereference the commit explicitly so the response names the
        // root tree object whose bytes are being verified.
        let treeish = format!("{commit}^{{tree}}");
        self.load_treeish_object(&treeish, commit.len(), None).await
    }

    async fn load_treeish_object(
        &self,
        treeish: &str,
        object_id_len: usize,
        expected: Option<&str>,
    ) -> Result<VerifiedTree, GitSourceError> {
        let mut entries = Vec::new();
        let mut paths = BTreeSet::new();
        let mut reported_id = None;
        for page in 1..=MAX_TREE_PAGES {
            let mut url =
                self.endpoint(&["repos", self.owner(), self.repo(), "git", "trees", treeish])?;
            url.query_pairs_mut()
                .append_pair("recursive", "false")
                .append_pair("page", &page.to_string())
                .append_pair("per_page", &TREE_PAGE_SIZE.to_string());
            let response: TreeResponse = self.get_json(url, METADATA_RESPONSE_LIMIT).await?;
            git_digest(&response.sha).ok_or(GitSourceError::InvalidObjectId)?;
            if response.sha.len() != object_id_len
                || expected.is_some_and(|expected| expected != response.sha)
                || reported_id
                    .as_ref()
                    .is_some_and(|reported: &String| reported != &response.sha)
            {
                return Err(GitSourceError::ObjectMismatch);
            }
            reported_id.get_or_insert(response.sha.clone());
            let count = response.tree.len();
            for entry in response.tree {
                validate_tree_entry(&entry, object_id_len)?;
                if !paths.insert(entry.path.clone()) {
                    return Err(GitSourceError::UnsupportedTreeEntry);
                }
                entries.push(entry);
                if entries.len() > MAX_TREE_ENTRIES {
                    return Err(GitSourceError::TreeTooLarge);
                }
            }
            if response
                .total_count
                .is_some_and(|total| total > MAX_TREE_ENTRIES)
            {
                return Err(GitSourceError::TreeTooLarge);
            }
            let complete = response
                .total_count
                .is_some_and(|total| entries.len() >= total)
                || !response.truncated && count < TREE_PAGE_SIZE;
            if complete {
                entries.sort_by(git_tree_order);
                let body = encode_tree(&entries, object_id_len)?;
                let id = git_object_id("tree", &body, object_id_len)?;
                if response.sha != id {
                    return Err(GitSourceError::ObjectMismatch);
                }
                return Ok(VerifiedTree { id, entries });
            }
        }
        Err(GitSourceError::TreeTooLarge)
    }

    async fn load_blob(&self, entry: &TreeEntry) -> Result<Vec<u8>, GitSourceError> {
        let _capacity = self
            .blob_capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| GitSourceError::CapacityExhausted)?;
        let response: BlobResponse = self
            .get_json(
                self.endpoint(&[
                    "repos",
                    self.owner(),
                    self.repo(),
                    "git",
                    "blobs",
                    &entry.sha,
                ])?,
                BLOB_RESPONSE_LIMIT,
            )
            .await?;
        if response.sha != entry.sha || response.encoding != "base64" {
            return Err(GitSourceError::UnsupportedTreeEntry);
        }
        let mut encoded = response.content;
        encoded.retain(|character| !character.is_ascii_whitespace());
        let bytes = STANDARD
            .decode(encoded.as_bytes())
            .map_err(|_| GitSourceError::UnsupportedTreeEntry)?;
        if entry.size != Some(bytes.len() as u64) || bytes.len() as u64 > MAX_SKILL_TOTAL_BYTES {
            return Err(GitSourceError::UnsupportedTreeEntry);
        }
        if git_object_id("blob", &bytes, entry.sha.len())? != entry.sha {
            return Err(GitSourceError::ObjectMismatch);
        }
        Ok(bytes)
    }

    async fn get_json<T: DeserializeOwned>(
        &self,
        url: Url,
        limit: usize,
    ) -> Result<T, GitSourceError> {
        let mut request = self
            .http
            .get(url)
            .header(header::ACCEPT, "application/json");
        if let Some(name) = &self.config.token_env {
            let token = std::env::var(name)
                .ok()
                .filter(|value| !value.is_empty())
                .ok_or(GitSourceError::CredentialUnavailable)?;
            request = request.header(header::AUTHORIZATION, format!("token {token}"));
        }
        let response = request.send().await.map_err(GitSourceError::Request)?;
        if !response.status().is_success() {
            return Err(GitSourceError::HttpStatus(response.status()));
        }
        let body = read_body_capped(response, limit)
            .await
            .map_err(|_| GitSourceError::ResponseTooLarge)?;
        serde_json::from_slice(&body).map_err(GitSourceError::InvalidResponse)
    }

    fn endpoint(&self, segments: &[&str]) -> Result<Url, GitSourceError> {
        let mut url = self.config.api_url.clone();
        url.path_segments_mut()
            .map_err(|_| GitSourceError::InvalidSource)?
            .pop_if_empty()
            .extend(segments);
        Ok(url)
    }

    fn owner(&self) -> &str {
        self.config.repository.split_once('/').expect("validated").0
    }

    fn repo(&self) -> &str {
        self.config.repository.split_once('/').expect("validated").1
    }

    fn in_configured_root(&self, path: &str) -> bool {
        self.config
            .roots
            .iter()
            .any(|root| path.starts_with(&format!("{root}/")))
    }
}

fn validate_catalog_metadata_budget(
    tree: &[TreeEntry],
    skill_roots: &[String],
) -> Result<(), GitSourceError> {
    if skill_roots.len() > MAX_CATALOG_SKILLS {
        return Err(GitSourceError::CatalogTooLarge);
    }
    let declared_bytes = skill_roots.iter().try_fold(0_u64, |total, root| {
        let path = format!("{root}/SKILL.md");
        let size = tree
            .iter()
            .find(|entry| entry.path == path)
            .and_then(|entry| entry.size)
            .ok_or(GitSourceError::UnsupportedTreeEntry)?;
        total
            .checked_add(size)
            .ok_or(GitSourceError::CatalogTooLarge)
    })?;
    if declared_bytes > MAX_CATALOG_SKILL_METADATA_BYTES {
        return Err(GitSourceError::CatalogTooLarge);
    }
    Ok(())
}

fn validated_skill_name(
    frontmatter: &serde_json::Map<String, serde_json::Value>,
) -> Result<&str, GitSourceError> {
    frontmatter
        .get("name")
        .and_then(serde_json::Value::as_str)
        .filter(|name| valid_skill_name(name))
        .ok_or(GitSourceError::InvalidSkillMetadata)
}

#[async_trait]
impl SkillCatalogSource for GitSkillSource {
    async fn restore(
        &self,
        identity: &CatalogSourceIdentity,
    ) -> Result<SkillCatalogSnapshot, SkillSourceError> {
        let origin = format!(
            "git+{}/{}",
            self.config.api_url.as_str().trim_end_matches('/'),
            self.config.repository
        );
        let reference = format!("{}@{}", self.config.repository, self.config.reference);
        let digest = identity
            .resolved_digest
            .strip_prefix("git-sha1:")
            .or_else(|| identity.resolved_digest.strip_prefix("git-sha256:"))
            .filter(|digest| {
                git_digest(digest).as_deref() == Some(identity.resolved_digest.as_str())
            });
        let tree = identity
            .resolved_tree_digest
            .split_once(':')
            .map(|(_, tree)| tree)
            .filter(|tree| {
                git_digest(tree).as_deref() == Some(identity.resolved_tree_digest.as_str())
            });
        if identity.origin != origin
            || identity.reference != reference
            || digest.is_none()
            || tree.is_none()
        {
            return Err(SkillSourceError::Unavailable(Box::new(
                GitSourceError::InvalidSource,
            )));
        }
        let snapshot = tokio::time::timeout(
            self.config.snapshot_timeout,
            // Configured pins select new observations. Historical recovery is
            // instead pinned to the exact identity retained by the review store.
            self.load_snapshot_at(digest.expect("validated digest"), digest, tree),
        )
        .await
        .map_err(|_| {
            SkillSourceError::Unavailable(Box::new(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "skill metadata restoration timed out",
            )))
        })?
        .map_err(|error| SkillSourceError::Unavailable(Box::new(error)))?;
        if snapshot.source() != identity {
            return Err(SkillSourceError::Unavailable(Box::new(
                GitSourceError::CommitMismatch,
            )));
        }
        Ok(snapshot)
    }

    async fn load(&self) -> Result<SkillCatalogSnapshot, SkillSourceError> {
        self.load_snapshot().await.map_err(|error| match error {
            GitSourceError::Catalog(error) => SkillSourceError::Invalid(error),
            other => SkillSourceError::Unavailable(Box::new(other)),
        })
    }
}

#[derive(Clone)]
struct GitResourceLoader {
    source: GitSkillSource,
    resources: Arc<BTreeMap<String, RemoteResource>>,
}

#[async_trait]
impl SkillResourceLoader for GitResourceLoader {
    async fn load(
        &self,
        descriptor: &SkillResourceDescriptor,
    ) -> Result<Vec<u8>, SkillResourceLoadError> {
        let resource = self
            .resources
            .get(&descriptor.uri)
            .ok_or_else(|| unavailable("resource is absent from the indexed revision"))?;
        if &resource.descriptor != descriptor {
            return Err(SkillResourceLoadError::IdentityMismatch(
                descriptor.uri.clone(),
            ));
        }
        let entry = TreeEntry {
            path: resource.path.clone(),
            mode: "100644".to_owned(),
            kind: "blob".to_owned(),
            sha: resource.sha.clone(),
            size: Some(descriptor.size),
        };
        self.source
            .load_blob(&entry)
            .await
            .map_err(|error| SkillResourceLoadError::Unavailable(Box::new(error)))
    }
}

fn unavailable(message: &'static str) -> SkillResourceLoadError {
    SkillResourceLoadError::Unavailable(Box::new(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        message,
    )))
}

#[derive(Debug, Clone)]
struct RemoteResource {
    descriptor: SkillResourceDescriptor,
    path: String,
    sha: String,
}

#[derive(Debug, Deserialize)]
struct CommitResponse {
    sha: String,
}

#[derive(Debug, Deserialize)]
struct TreeResponse {
    sha: String,
    #[serde(default)]
    tree: Vec<TreeEntry>,
    #[serde(default)]
    truncated: bool,
    total_count: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
struct TreeEntry {
    path: String,
    mode: String,
    #[serde(rename = "type")]
    kind: String,
    sha: String,
    size: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct BlobResponse {
    content: String,
    encoding: String,
    sha: String,
}

struct VerifiedTree {
    id: String,
    entries: Vec<TreeEntry>,
}

#[derive(Default)]
struct TreePathBudget {
    entries: usize,
    path_bytes: usize,
}

impl TreePathBudget {
    fn expand(
        &mut self,
        prefix: &str,
        child: &str,
        parent_depth: usize,
    ) -> Result<(String, usize), GitSourceError> {
        let depth = parent_depth
            .checked_add(1)
            .filter(|depth| *depth <= MAX_TREE_DEPTH)
            .ok_or(GitSourceError::TreeTooLarge)?;
        let path_bytes = prefix
            .len()
            .checked_add(1)
            .and_then(|bytes| bytes.checked_add(child.len()))
            .filter(|bytes| *bytes <= MAX_GIT_PATH_BYTES)
            .ok_or(GitSourceError::TreeTooLarge)?;
        self.entries = self
            .entries
            .checked_add(1)
            .filter(|entries| *entries <= MAX_TREE_ENTRIES)
            .ok_or(GitSourceError::TreeTooLarge)?;
        self.path_bytes = self
            .path_bytes
            .checked_add(path_bytes)
            .filter(|bytes| *bytes <= MAX_CATALOG_PATH_BYTES)
            .ok_or(GitSourceError::TreeTooLarge)?;

        let mut path = String::with_capacity(path_bytes);
        path.push_str(prefix);
        path.push('/');
        path.push_str(child);
        Ok((path, depth))
    }
}

fn index_tree_entries(
    prefix: &str,
    parent_depth: usize,
    children: Vec<TreeEntry>,
    budget: &mut TreePathBudget,
    entries: &mut BTreeMap<String, TreeEntry>,
    pending: &mut Vec<(String, usize, String)>,
) -> Result<(), GitSourceError> {
    for mut entry in children {
        let (path, depth) = budget.expand(prefix, &entry.path, parent_depth)?;
        if entry.kind == "tree" {
            pending.push((path, depth, entry.sha));
        } else {
            entry.path = path;
            entries.insert(entry.path.clone(), entry);
        }
    }
    Ok(())
}

fn validate_tree_entry(entry: &TreeEntry, object_id_len: usize) -> Result<(), GitSourceError> {
    if entry.path.is_empty()
        || entry.path.len() > MAX_GIT_PATH_SEGMENT_BYTES
        || entry.path == "."
        || entry.path == ".."
        || entry.path.contains(['/', '\0'])
        || entry.sha.len() != object_id_len
        || git_digest(&entry.sha).is_none()
    {
        return Err(GitSourceError::UnsupportedTreeEntry);
    }
    let valid_mode = matches!(
        (entry.mode.as_str(), entry.kind.as_str()),
        ("040000", "tree") | ("100644" | "100755" | "120000", "blob") | ("160000", "commit")
    );
    if !valid_mode {
        return Err(GitSourceError::UnsupportedTreeEntry);
    }
    Ok(())
}

fn git_tree_order(left: &TreeEntry, right: &TreeEntry) -> Ordering {
    git_tree_sort_key(left).cmp(&git_tree_sort_key(right))
}

fn git_tree_sort_key(entry: &TreeEntry) -> Vec<u8> {
    let mut key = entry.path.as_bytes().to_vec();
    key.push(if entry.kind == "tree" { b'/' } else { 0 });
    key
}

fn encode_tree(entries: &[TreeEntry], object_id_len: usize) -> Result<Vec<u8>, GitSourceError> {
    let mut body = Vec::new();
    for entry in entries {
        let mode = if entry.kind == "tree" {
            "40000"
        } else {
            entry.mode.as_str()
        };
        body.extend_from_slice(mode.as_bytes());
        body.push(b' ');
        body.extend_from_slice(entry.path.as_bytes());
        body.push(0);
        body.extend_from_slice(&decode_object_id(&entry.sha, object_id_len)?);
    }
    Ok(body)
}

fn decode_object_id(value: &str, object_id_len: usize) -> Result<Vec<u8>, GitSourceError> {
    if value.len() != object_id_len || !matches!(object_id_len, 40 | 64) {
        return Err(GitSourceError::InvalidObjectId);
    }
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(GitSourceError::InvalidObjectId);
    }
    pairs
        .iter()
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or(GitSourceError::InvalidObjectId)?;
            let low = hex_nibble(pair[1]).ok_or(GitSourceError::InvalidObjectId)?;
            Ok(high << 4 | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn git_object_id(kind: &str, body: &[u8], object_id_len: usize) -> Result<String, GitSourceError> {
    let header = format!("{kind} {}\0", body.len());
    let bytes = match object_id_len {
        40 => {
            let mut hasher = Sha1::new();
            hasher.update(header.as_bytes());
            hasher.update(body);
            hasher.finalize().to_vec()
        }
        64 => {
            let mut hasher = Sha256::new();
            hasher.update(header.as_bytes());
            hasher.update(body);
            hasher.finalize().to_vec()
        }
        _ => return Err(GitSourceError::InvalidObjectId),
    };
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn valid_api_url(url: &Url) -> bool {
    (url.scheme() == "https" || url.scheme() == "http" && url.host_str().is_some_and(is_loopback))
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

fn is_loopback(host: &str) -> bool {
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn valid_repository(repository: &str) -> bool {
    let mut parts = repository.split('/');
    matches!((parts.next(), parts.next(), parts.next()), (Some(owner), Some(repo), None)
        if valid_path_name(owner) && valid_path_name(repo))
}

fn valid_source_id(value: &str) -> bool {
    valid_path_name(value)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_root(value: &str) -> bool {
    !value.starts_with('/')
        && !value.ends_with('/')
        && value.len() <= MAX_GIT_PATH_BYTES
        && value.split('/').count() < MAX_TREE_DEPTH
        && value
            .split('/')
            .all(|segment| segment.len() <= MAX_GIT_PATH_SEGMENT_BYTES && valid_path_name(segment))
}

fn roots_overlap(roots: &[String]) -> bool {
    roots.iter().enumerate().any(|(index, root)| {
        roots.iter().skip(index + 1).any(|other| {
            root == other
                || root.starts_with(&format!("{other}/"))
                || other.starts_with(&format!("{root}/"))
        })
    })
}

fn valid_path_name(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.chars().any(char::is_control)
        && !value.contains(['\\', '%'])
}

fn invalid_segment(value: &str) -> bool {
    !valid_path_name(value)
}

fn git_digest(commit: &str) -> Option<String> {
    let prefix = match commit.len() {
        40 => "git-sha1:",
        64 => "git-sha256:",
        _ => return None,
    };
    commit
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        .then(|| format!("{prefix}{commit}"))
}

fn media_type(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, extension)| extension) {
        Some("md") => "text/markdown",
        Some("js") | Some("mjs") => "text/javascript",
        Some("json") => "application/json",
        Some("yaml" | "yml") => "application/yaml",
        Some("txt") => "text/plain",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("pdf") => "application/pdf",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::{Request, State},
        http::StatusCode,
        response::IntoResponse,
        routing::any,
        Json, Router,
    };
    use std::sync::Mutex;

    fn config() -> SkillsGitConfig {
        SkillsGitConfig {
            api_url: Url::parse("https://git.example/api/v1").unwrap(),
            repository: "team/skills".to_owned(),
            reference: "main".to_owned(),
            expected_commit: None,
            expected_tree: None,
            source_id: "homelab".to_owned(),
            roots: vec!["plugins".to_owned()],
            token_env: None,
            refresh_interval: None,
            snapshot_timeout: DEFAULT_GIT_SNAPSHOT_TIMEOUT,
        }
    }

    #[test]
    fn validates_direct_git_source_without_registry_credentials() {
        let http = http_client::client(http_client::Profile::Slow).unwrap();
        let source = GitSkillSource::new(http, config()).expect("valid source");
        assert_eq!(source.owner(), "team");
        assert_eq!(source.repo(), "skills");
        assert!(source.config.token_env.is_none());
    }

    #[test]
    fn pin_accepts_only_full_lowercase_git_object_ids() {
        assert_eq!(
            git_digest(&"a".repeat(40)),
            Some(format!("git-sha1:{}", "a".repeat(40)))
        );
        assert!(git_digest("main").is_none());
        assert!(git_digest(&"A".repeat(40)).is_none());
    }

    #[test]
    fn object_hashing_matches_git_blob_and_tree_format() {
        assert_eq!(
            git_object_id("blob", b"what is up, doc?", 40).unwrap(),
            "bd9dbf5aae1a3862dd1526723246b20206e5fc37"
        );
        let tree = vec![TreeEntry {
            path: "test.txt".to_owned(),
            mode: "100644".to_owned(),
            kind: "blob".to_owned(),
            sha: "83baae61804e65cc73a7201a7252750c76066a30".to_owned(),
            size: Some(10),
        }];
        assert_eq!(tree_id(&tree), "d8329fc1cc938780ffdd9f94e0d364e0ea74f579");
    }

    #[test]
    fn source_rejects_credentials_in_url_and_path_traversal_roots() {
        let http = http_client::client(http_client::Profile::Slow).unwrap();
        let mut invalid = config();
        invalid.api_url = Url::parse("https://user:secret@git.example/api/v1").unwrap();
        assert!(GitSkillSource::new(http.clone(), invalid).is_err());
        let mut invalid = config();
        invalid.roots = vec!["plugins/../private".to_owned()];
        assert!(GitSkillSource::new(http, invalid).is_err());
    }

    #[test]
    fn tree_path_budget_refuses_unbounded_expansion_before_allocation() {
        let mut budget = TreePathBudget::default();
        assert!(matches!(
            budget.expand(&"a".repeat(MAX_GIT_PATH_BYTES), "b", 1),
            Err(GitSourceError::TreeTooLarge)
        ));

        let mut budget = TreePathBudget::default();
        assert!(matches!(
            budget.expand("parent", "child", MAX_TREE_DEPTH),
            Err(GitSourceError::TreeTooLarge)
        ));

        let mut budget = TreePathBudget {
            entries: 0,
            path_bytes: MAX_CATALOG_PATH_BYTES - 1,
        };
        assert!(matches!(
            budget.expand("parent", "child", 1),
            Err(GitSourceError::TreeTooLarge)
        ));

        let mut budget = TreePathBudget {
            entries: MAX_TREE_ENTRIES,
            path_bytes: 0,
        };
        assert!(matches!(
            budget.expand("parent", "child", 1),
            Err(GitSourceError::TreeTooLarge)
        ));

        let oversized_segment = tree_entry(
            &"x".repeat(MAX_GIT_PATH_SEGMENT_BYTES + 1),
            "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
        );
        assert!(matches!(
            validate_tree_entry(&oversized_segment, 40),
            Err(GitSourceError::UnsupportedTreeEntry)
        ));
    }

    #[test]
    fn tree_budget_rejects_siblings_before_loading_their_children() {
        let children = vec![
            tree_entry("first", &"a".repeat(40)),
            tree_entry("second", &"b".repeat(40)),
        ];
        let mut budget = TreePathBudget {
            entries: MAX_TREE_ENTRIES - 1,
            path_bytes: 0,
        };
        let mut entries = BTreeMap::new();
        let mut pending = Vec::new();

        assert!(matches!(
            index_tree_entries(
                "plugins",
                1,
                children,
                &mut budget,
                &mut entries,
                &mut pending,
            ),
            Err(GitSourceError::TreeTooLarge)
        ));
        assert!(entries.is_empty());
        assert_eq!(pending, vec![("plugins/first".into(), 2, "a".repeat(40))]);
    }

    #[test]
    fn maps_common_skill_resources_to_canonical_media_types() {
        assert_eq!(media_type("SKILL.md"), "text/markdown");
        assert_eq!(media_type("scripts/run.js"), "text/javascript");
        assert_eq!(media_type("assets/data.bin"), "application/octet-stream");
    }

    fn skill_root_entry(root: &str, size: u64) -> TreeEntry {
        TreeEntry {
            path: format!("{root}/SKILL.md"),
            mode: "100644".into(),
            kind: "blob".into(),
            sha: "a".repeat(40),
            size: Some(size),
        }
    }

    #[test]
    fn catalog_metadata_budget_rejects_excessive_declared_bytes_before_blob_loading() {
        let roots = vec!["plugins/demo".to_owned()];
        let tree = vec![skill_root_entry(
            &roots[0],
            MAX_CATALOG_SKILL_METADATA_BYTES + 1,
        )];

        assert!(matches!(
            validate_catalog_metadata_budget(&tree, &roots),
            Err(GitSourceError::CatalogTooLarge)
        ));
    }

    #[test]
    fn catalog_metadata_budget_rejects_excessive_skill_count() {
        let roots = (0..=MAX_CATALOG_SKILLS)
            .map(|index| format!("plugins/skill-{index}"))
            .collect::<Vec<_>>();
        let tree = roots
            .iter()
            .map(|root| skill_root_entry(root, 1))
            .collect::<Vec<_>>();

        assert!(matches!(
            validate_catalog_metadata_budget(&tree, &roots),
            Err(GitSourceError::CatalogTooLarge)
        ));
    }

    #[test]
    fn oversized_skill_name_is_refused_before_resource_projection() {
        let frontmatter = serde_json::Map::from_iter([(
            "name".to_owned(),
            serde_json::Value::String("a".repeat(65)),
        )]);

        assert!(matches!(
            validated_skill_name(&frontmatter),
            Err(GitSourceError::InvalidSkillMetadata)
        ));
    }

    #[derive(Clone)]
    struct TestApi {
        calls: Arc<Mutex<Vec<String>>>,
        commit: String,
        root_id: String,
        root: Vec<TreeEntry>,
        trees: Arc<Mutex<BTreeMap<String, Vec<TreeEntry>>>>,
        blobs: Arc<BTreeMap<String, Vec<u8>>>,
        blob_overrides: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    }

    impl Default for TestApi {
        fn default() -> Self {
            Self::with_object_width(40)
        }
    }

    impl TestApi {
        fn with_object_width(width: usize) -> Self {
            let skill =
                b"---\nname: lazy\ndescription: Load files only when requested\n---\n# Lazy\n";
            let script = b"return { ok: true };\n";
            let root_blob = blob_entry_with_width("SKILL.md", skill, width);
            let script_blob = blob_entry_with_width("run.js", script, width);
            let scripts = vec![script_blob.clone()];
            let scripts_id = tree_id_with_width(&scripts, width);
            let lazy = vec![root_blob.clone(), tree_entry("scripts", &scripts_id)];
            let lazy_id = tree_id_with_width(&lazy, width);
            let plugins = vec![tree_entry("lazy", &lazy_id)];
            let plugins_id = tree_id_with_width(&plugins, width);
            let root = vec![
                tree_entry("plugins", &plugins_id),
                tree_entry("unrelated", &git_object_id("tree", b"", width).unwrap()),
            ];
            let root_id = tree_id_with_width(&root, width);
            Self {
                calls: Arc::default(),
                commit: "a".repeat(width),
                root_id,
                root,
                trees: Arc::new(Mutex::new(BTreeMap::from([
                    (plugins_id, plugins),
                    (lazy_id, lazy),
                    (scripts_id, scripts),
                ]))),
                blobs: Arc::new(BTreeMap::from([
                    (root_blob.sha, skill.to_vec()),
                    (script_blob.sha, script.to_vec()),
                ])),
                blob_overrides: Arc::default(),
            }
        }
    }

    fn blob_entry(path: &str, bytes: &[u8]) -> TreeEntry {
        blob_entry_with_width(path, bytes, 40)
    }

    fn blob_entry_with_width(path: &str, bytes: &[u8], width: usize) -> TreeEntry {
        TreeEntry {
            path: path.to_owned(),
            mode: "100644".to_owned(),
            kind: "blob".to_owned(),
            sha: git_object_id("blob", bytes, width).expect("blob id"),
            size: Some(bytes.len() as u64),
        }
    }

    fn tree_entry(path: &str, sha: &str) -> TreeEntry {
        TreeEntry {
            path: path.to_owned(),
            mode: "040000".to_owned(),
            kind: "tree".to_owned(),
            sha: sha.to_owned(),
            size: Some(0),
        }
    }

    fn tree_id(entries: &[TreeEntry]) -> String {
        tree_id_with_width(entries, 40)
    }

    fn tree_id_with_width(entries: &[TreeEntry], width: usize) -> String {
        let mut entries = entries.to_vec();
        entries.sort_by(git_tree_order);
        let body = encode_tree(&entries, width).expect("tree body");
        git_object_id("tree", &body, width).expect("tree id")
    }

    async fn git_api(State(state): State<TestApi>, request: Request) -> impl IntoResponse {
        let path = request.uri().path().to_owned();
        state.calls.lock().expect("calls lock").push(path.clone());
        let value = if path.ends_with("/git/commits/main")
            || path.ends_with(&format!("/git/commits/{}", state.commit))
        {
            serde_json::json!({"sha": state.commit, "tree": {"sha": state.commit}})
        } else if let Some(treeish) = path.rsplit_once("/git/trees/").map(|(_, id)| id) {
            let (sha, entries) = if treeish.starts_with(&state.commit) || treeish == state.root_id {
                (state.root_id.clone(), Some(state.root.clone()))
            } else {
                (
                    treeish.to_owned(),
                    state
                        .trees
                        .lock()
                        .expect("trees lock")
                        .get(treeish)
                        .cloned(),
                )
            };
            let Some(entries) = entries else {
                return (StatusCode::NOT_FOUND, Json(serde_json::json!({}))).into_response();
            };
            serde_json::json!({
                "sha": sha,
                "truncated": false,
                "total_count": entries.len(),
                "tree": entries,
            })
        } else if let Some(sha) = path.rsplit_once("/git/blobs/").map(|(_, id)| id) {
            let bytes = state
                .blob_overrides
                .lock()
                .expect("blob overrides lock")
                .get(sha)
                .cloned()
                .or_else(|| state.blobs.get(sha).cloned());
            let Some(bytes) = bytes else {
                return (StatusCode::NOT_FOUND, Json(serde_json::json!({}))).into_response();
            };
            serde_json::json!({"sha":sha,"encoding":"base64","content":STANDARD.encode(bytes)})
        } else {
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({}))).into_response();
        };
        (StatusCode::OK, Json(value)).into_response()
    }

    async fn spawn_test_api(state: TestApi) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener");
        let address = listener.local_addr().expect("listener address");
        let app = Router::new()
            .route("/{*path}", any(git_api))
            .with_state(state);
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test server");
        });
        (address, server)
    }

    fn source_for_test_api(address: std::net::SocketAddr, state: &TestApi) -> GitSkillSource {
        let mut source_config = config();
        source_config.api_url = Url::parse(&format!("http://{address}/api/v1")).unwrap();
        source_config.expected_commit = Some(state.commit.clone());
        source_config.expected_tree = Some(state.root_id.clone());
        GitSkillSource::new(
            http_client::client(http_client::Profile::Slow).unwrap(),
            source_config,
        )
        .expect("valid source")
    }

    #[tokio::test]
    async fn gitea_commit_treeish_uses_the_dereferenced_root_tree_identity() {
        let state = TestApi::default();
        let (address, server) = spawn_test_api(state.clone()).await;
        let source = source_for_test_api(address, &state);

        let snapshot = source.load_snapshot().await.expect("metadata snapshot");
        assert_eq!(
            snapshot.source().resolved_tree_digest,
            format!("git-sha1:{}", state.root_id)
        );
        assert!(state
            .calls
            .lock()
            .expect("calls lock")
            .iter()
            .any(|path| path.contains(&format!("/git/trees/{}^%7Btree%7D", state.commit))));
        server.abort();
    }

    #[tokio::test]
    async fn restore_uses_the_recorded_commit_and_refuses_foreign_or_mismatched_identity() {
        for width in [40, 64] {
            let state = TestApi::with_object_width(width);
            let (address, server) = spawn_test_api(state.clone()).await;
            let mut source = source_for_test_api(address, &state);
            let snapshot = source.load_snapshot().await.unwrap();
            source.config.expected_commit = Some("f".repeat(width));
            source.config.expected_tree = Some("f".repeat(width));
            assert!(matches!(
                source.load_snapshot().await,
                Err(GitSourceError::CommitMismatch)
            ));
            state.calls.lock().unwrap().clear();
            let restored = source.restore(snapshot.source()).await.unwrap();
            assert_eq!(restored.revision(), snapshot.revision());
            assert!(state
                .calls
                .lock()
                .unwrap()
                .iter()
                .any(|path| { path.ends_with(&format!("/git/commits/{}", state.commit)) }));
            assert!(!state
                .calls
                .lock()
                .unwrap()
                .iter()
                .any(|path| { path.ends_with("/git/commits/main") }));
            state.calls.lock().unwrap().clear();
            let mut foreign = snapshot.source().clone();
            foreign.origin.push_str("/other");
            assert!(source.restore(&foreign).await.is_err());
            assert!(state.calls.lock().unwrap().is_empty());
            let mut mismatch = snapshot.source().clone();
            mismatch.resolved_tree_digest = git_digest(&"b".repeat(width)).unwrap();
            assert!(source.restore(&mismatch).await.is_err());
            server.abort();
        }
    }

    #[tokio::test]
    async fn initial_skill_publication_advances_the_client_catalog_signal() {
        let state = TestApi::default();
        let (address, server) = spawn_test_api(state.clone()).await;
        let epoch = waygate_mcp::ToolCatalogEpoch::new();
        let mut changes = epoch.subscribe();
        let catalog = Arc::new(ReloadableSkillCatalog::default());
        let source = Arc::new(ObservedSkillSource {
            source: Arc::new(source_for_test_api(address, &state)),
            reviews: None,
            tenants: None,
        });
        let runtime = SkillsRuntime {
            catalog: catalog.clone(),
            reviewed: Arc::new(ReviewedSkillCatalog::new(
                catalog.clone(),
                source.clone(),
                None,
            )),
            source,
            refresh_interval: None,
            snapshot_timeout: Duration::from_secs(5),
        };
        runtime
            .spawn_refresh(CancellationToken::new(), epoch.clone())
            .await
            .unwrap();
        assert!(catalog.current().is_some());
        assert!(changes.has_changed().unwrap());
        assert_eq!(*changes.borrow_and_update(), epoch.current());
        server.abort();
    }

    #[tokio::test]
    async fn refresh_reads_only_skill_metadata_and_resource_read_fetches_one_blob() {
        let state = TestApi::default();
        let (address, server) = spawn_test_api(state.clone()).await;
        let source = source_for_test_api(address, &state);

        let snapshot = source.load_snapshot().await.expect("metadata snapshot");
        assert_eq!(
            snapshot.source().resolved_digest,
            format!("git-sha1:{}", state.commit)
        );
        assert_eq!(
            snapshot.source().resolved_tree_digest,
            format!("git-sha1:{}", state.root_id)
        );
        let script_sha = git_object_id("blob", b"return { ok: true };\n", 40).unwrap();
        let script_path = format!("/git/blobs/{script_sha}");
        assert!(!state
            .calls
            .lock()
            .expect("calls lock")
            .iter()
            .any(|path| path.ends_with(&script_path)));

        let loaded = snapshot
            .load_resource("skill://homelab/lazy/scripts/run.js")
            .await
            .expect("resource read")
            .expect("indexed script");
        assert_eq!(loaded.bytes.as_ref(), b"return { ok: true };\n");
        let identity = snapshot
            .resource_identity(
                "skill://homelab/lazy/scripts/run.js",
                loaded.content_digest.clone(),
            )
            .expect("resource identity");
        assert_eq!(identity.source_path, "plugins/lazy/scripts/run.js");
        assert_eq!(identity.source_object, format!("git-sha1:{script_sha}"));
        assert_eq!(
            identity.revision.source_tree_digest,
            format!("git-sha1:{}", state.root_id)
        );
        assert_eq!(identity.resource_digest, loaded.content_digest);
        assert_eq!(
            state
                .calls
                .lock()
                .expect("calls lock")
                .iter()
                .filter(|path| path.ends_with(&script_path))
                .count(),
            1
        );
        server.abort();
    }

    #[tokio::test]
    async fn resource_read_rejects_same_length_bytes_under_an_echoed_blob_id() {
        let state = TestApi::default();
        let (address, server) = spawn_test_api(state.clone()).await;
        let source = source_for_test_api(address, &state);
        let snapshot = source.load_snapshot().await.expect("metadata snapshot");
        let expected = b"return { ok: true };\n";
        let replacement = b"return { no: true };\n";
        assert_eq!(expected.len(), replacement.len());
        let script_sha = git_object_id("blob", expected, 40).unwrap();
        state
            .blob_overrides
            .lock()
            .expect("blob overrides lock")
            .insert(script_sha, replacement.to_vec());

        assert!(snapshot
            .load_resource("skill://homelab/lazy/scripts/run.js")
            .await
            .is_err());
        server.abort();
    }

    #[tokio::test]
    async fn refresh_rejects_tree_entries_that_do_not_hash_to_the_parent_object_id() {
        let state = TestApi::default();
        let script_tree_id = state
            .trees
            .lock()
            .expect("trees lock")
            .iter()
            .find(|(_, entries)| entries.iter().any(|entry| entry.path == "run.js"))
            .map(|(id, _)| id.clone())
            .expect("scripts tree");
        state
            .trees
            .lock()
            .expect("trees lock")
            .get_mut(&script_tree_id)
            .expect("scripts tree")
            .first_mut()
            .expect("script entry")
            .sha = "f".repeat(40);
        let (address, server) = spawn_test_api(state.clone()).await;
        let source = source_for_test_api(address, &state);

        assert!(matches!(
            source.load_snapshot().await,
            Err(GitSourceError::ObjectMismatch)
        ));
        server.abort();
    }

    #[tokio::test]
    async fn pinned_commit_rejects_root_bytes_that_do_not_match_its_declared_tree() {
        let mut state = TestApi::default();
        state.root.push(TreeEntry {
            path: "unexpected".to_owned(),
            mode: "040000".to_owned(),
            kind: "tree".to_owned(),
            sha: "4b825dc642cb6eb9a060e54bf8d69288fbee4904".to_owned(),
            size: Some(0),
        });
        let (address, server) = spawn_test_api(state.clone()).await;
        let mut source_config = config();
        source_config.api_url = Url::parse(&format!("http://{address}/api/v1")).unwrap();
        source_config.expected_commit = Some(state.commit.clone());
        source_config.expected_tree = None;
        let source = GitSkillSource::new(
            http_client::client(http_client::Profile::Slow).unwrap(),
            source_config,
        )
        .expect("valid source");

        assert!(matches!(
            source.load_snapshot().await,
            Err(GitSourceError::ObjectMismatch)
        ));
        server.abort();
    }

    #[tokio::test]
    async fn refresh_rejects_a_root_tree_that_does_not_match_the_operator_pin() {
        let state = TestApi::default();
        let (address, server) = spawn_test_api(state.clone()).await;
        let mut source_config = config();
        source_config.api_url = Url::parse(&format!("http://{address}/api/v1")).unwrap();
        source_config.expected_tree = Some("f".repeat(40));
        let source = GitSkillSource::new(
            http_client::client(http_client::Profile::Slow).unwrap(),
            source_config,
        )
        .expect("valid source");

        assert!(matches!(
            source.load_snapshot().await,
            Err(GitSourceError::TreeMismatch)
        ));
        server.abort();
    }

    #[tokio::test]
    async fn refresh_rejects_a_revision_that_does_not_match_the_operator_commit_assertion() {
        let state = TestApi::default();
        let (address, server) = spawn_test_api(state.clone()).await;
        let mut source_config = config();
        source_config.api_url = Url::parse(&format!("http://{address}/api/v1")).unwrap();
        source_config.expected_commit = Some("f".repeat(40));
        let source = GitSkillSource::new(
            http_client::client(http_client::Profile::Slow).unwrap(),
            source_config,
        )
        .expect("valid source");

        assert!(matches!(
            source.load_snapshot().await,
            Err(GitSourceError::CommitMismatch)
        ));
        server.abort();
    }

    #[tokio::test]
    async fn blob_capacity_refuses_work_before_an_outbound_request() {
        let source = GitSkillSource::new(
            http_client::client(http_client::Profile::Slow).unwrap(),
            config(),
        )
        .expect("valid source");
        let _capacity = source
            .blob_capacity
            .clone()
            .try_acquire_many_owned(MAX_CONCURRENT_GIT_BLOB_LOADS as u32)
            .expect("all blob slots");
        let entry = blob_entry("script.js", b"return true;\n");

        assert!(matches!(
            source.load_blob(&entry).await,
            Err(GitSourceError::CapacityExhausted)
        ));
    }
}
