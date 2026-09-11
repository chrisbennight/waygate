//! Canonical in-memory fakes — one per trait, one naming convention.
//!
//! [`InMemoryManifestStore`] replaces the two independent `ManifestStore`
//! mocks the `dashboard_render/` suite carried (a static stub and this recording
//! fake): the recording fake with a [`InMemoryManifestStore::seeded`]
//! constructor covers the static case too, so the stub is retired
//! (F7's "two independent mocks of the same trait" finding).

use std::sync::Arc;

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Default)]
pub struct InMemoryProfileStore {
    profiles: std::sync::Mutex<Vec<waygate_apikeys::Profile>>,
    delete_block: std::sync::Mutex<Option<i64>>,
    advance_before_conditional_delete: std::sync::Mutex<bool>,
}

impl InMemoryProfileStore {
    pub fn seed_profile(&self, tenant_id: &str, name: &str) -> Uuid {
        let id = Uuid::new_v4();
        self.seed(waygate_apikeys::Profile {
            id,
            tenant_id: tenant_id.to_owned(),
            name: name.to_owned(),
            description: None,
            max_ttl_seconds: 3_600,
            allowed_scopes: vec!["mcp:invoke".into()],
            allowed_servers: None,
            allowed_tools: None,
            requires_reason: true,
            requires_owner: true,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        });
        id
    }

    pub fn seed(&self, profile: waygate_apikeys::Profile) {
        self.profiles.lock().unwrap().push(profile);
    }

    pub fn snapshot(&self) -> Vec<waygate_apikeys::Profile> {
        self.profiles.lock().unwrap().clone()
    }

    pub fn len(&self) -> usize {
        self.profiles.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.profiles.lock().unwrap().is_empty()
    }

    pub fn set_delete_block(&self, live_refs: Option<i64>) {
        *self.delete_block.lock().unwrap() = live_refs;
    }

    pub fn advance_before_conditional_delete(&self) {
        *self.advance_before_conditional_delete.lock().unwrap() = true;
    }

    fn delete_matching(
        &self,
        tenant_id: &str,
        id: Uuid,
        expected_updated_at: Option<OffsetDateTime>,
    ) -> Result<bool, waygate_apikeys::ProfileStoreError> {
        let mut profiles = self.profiles.lock().unwrap();
        if expected_updated_at.is_some()
            && std::mem::take(&mut *self.advance_before_conditional_delete.lock().unwrap())
        {
            if let Some(profile) = profiles
                .iter_mut()
                .find(|profile| profile.tenant_id == tenant_id && profile.id == id)
            {
                profile.updated_at += time::Duration::SECOND;
            }
        }
        let matches = |profile: &waygate_apikeys::Profile| {
            profile.tenant_id == tenant_id
                && profile.id == id
                && expected_updated_at
                    .map(|expected| profile.updated_at == expected)
                    .unwrap_or(true)
        };
        if profiles.iter().any(matches) {
            if let Some(live_refs) = *self.delete_block.lock().unwrap() {
                return Err(waygate_apikeys::ProfileStoreError::Blocked { live_refs });
            }
        }
        let before = profiles.len();
        profiles.retain(|profile| !matches(profile));
        Ok(profiles.len() != before)
    }
}

#[async_trait]
impl waygate_apikeys::ProfileStore for InMemoryProfileStore {
    #[allow(clippy::too_many_arguments)]
    async fn create(
        &self,
        tenant_id: &str,
        name: &str,
        description: Option<&str>,
        max_ttl_seconds: i32,
        allowed_scopes: &[String],
        allowed_servers: Option<&[String]>,
        allowed_tools: Option<&[String]>,
        requires_reason: bool,
        requires_owner: bool,
    ) -> Result<waygate_apikeys::Profile, waygate_apikeys::ProfileStoreError> {
        let mut profiles = self.profiles.lock().unwrap();
        if profiles
            .iter()
            .any(|profile| profile.tenant_id == tenant_id && profile.name == name)
        {
            return Err(waygate_apikeys::ProfileStoreError::Conflict);
        }
        let profile = waygate_apikeys::Profile {
            id: Uuid::new_v4(),
            tenant_id: tenant_id.to_owned(),
            name: name.to_owned(),
            description: description.map(str::to_owned),
            max_ttl_seconds,
            allowed_scopes: allowed_scopes.to_vec(),
            allowed_servers: allowed_servers.map(<[String]>::to_vec),
            allowed_tools: allowed_tools.map(<[String]>::to_vec),
            requires_reason,
            requires_owner,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        profiles.push(profile.clone());
        Ok(profile)
    }

    async fn get(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<waygate_apikeys::Profile>, waygate_apikeys::ProfileStoreError> {
        Ok(self
            .profiles
            .lock()
            .unwrap()
            .iter()
            .find(|profile| profile.tenant_id == tenant_id && profile.id == id)
            .cloned())
    }

    async fn list(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<waygate_apikeys::Profile>, waygate_apikeys::ProfileStoreError> {
        let mut profiles: Vec<_> = self
            .profiles
            .lock()
            .unwrap()
            .iter()
            .filter(|profile| profile.tenant_id == tenant_id)
            .cloned()
            .collect();
        profiles.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(profiles)
    }

    async fn delete(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<bool, waygate_apikeys::ProfileStoreError> {
        self.delete_matching(tenant_id, id, None)
    }

    async fn delete_if_updated_at(
        &self,
        tenant_id: &str,
        id: Uuid,
        expected_updated_at: OffsetDateTime,
    ) -> Result<bool, waygate_apikeys::ProfileStoreError> {
        self.delete_matching(tenant_id, id, Some(expected_updated_at))
    }

    async fn delete_all_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<u64, waygate_apikeys::ProfileStoreError> {
        let mut profiles = self.profiles.lock().unwrap();
        let before = profiles.len();
        profiles.retain(|profile| profile.tenant_id != tenant_id);
        Ok((before - profiles.len()) as u64)
    }
}

pub struct InMemoryManifestStore {
    bundles: std::sync::Mutex<Vec<waygate_manifest_store::ManifestBundle>>,
    /// Turnstile pointer: the current live hash, or `None` until
    /// seeded. Modeled so the per-server write path's CAS round-trips.
    pointer: std::sync::Mutex<Option<String>>,
    heartbeats: std::sync::Mutex<Vec<waygate_manifest_store::ReplicaHeartbeat>>,
}

impl InMemoryManifestStore {
    pub fn seeded(content: &str) -> Arc<Self> {
        let b = waygate_manifest_store::ManifestBundle {
            id: Uuid::new_v4(),
            tenant_id: waygate_core::TenantId::DEFAULT.to_string(),
            version: 1,
            status: waygate_manifest_store::ManifestStatus::Published,
            content: content.to_string(),
            content_hash: waygate_manifest_store::content_hash(content),
            author: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            published_at: Some(OffsetDateTime::UNIX_EPOCH),
            published_by: None,
        };
        Arc::new(Self {
            bundles: std::sync::Mutex::new(vec![b]),
            pointer: std::sync::Mutex::new(None),
            heartbeats: std::sync::Mutex::new(Vec::new()),
        })
    }

    pub fn set_heartbeats(&self, heartbeats: Vec<waygate_manifest_store::ReplicaHeartbeat>) {
        *self.heartbeats.lock().unwrap() = heartbeats;
    }

    /// Force the turnstile pointer to `hash`, simulating another replica
    /// having advanced it out from under this one (for turnstile CAS tests).
    pub fn force_pointer(&self, hash: &str) {
        *self.pointer.lock().unwrap() = Some(hash.to_string());
    }

    /// Content of the newest published bundle — the active set.
    pub fn active_content(&self) -> String {
        let g = self.bundles.lock().unwrap();
        g.iter()
            .filter(|b| matches!(b.status, waygate_manifest_store::ManifestStatus::Published))
            .max_by_key(|b| b.version)
            .expect("a published bundle")
            .content
            .clone()
    }

    /// Current turnstile pointer value, to assert reconciliation.
    pub fn current_pointer(&self) -> Option<String> {
        self.pointer.lock().unwrap().clone()
    }
}

#[async_trait]
impl waygate_manifest_store::ManifestStore for InMemoryManifestStore {
    async fn active_bundle(
        &self,
        _t: &str,
    ) -> Result<waygate_manifest_store::ManifestBundle, waygate_manifest_store::ManifestError> {
        let g = self.bundles.lock().unwrap();
        g.iter()
            .filter(|b| matches!(b.status, waygate_manifest_store::ManifestStatus::Published))
            .max_by_key(|b| b.version)
            .cloned()
            .ok_or(waygate_manifest_store::ManifestError::NotFound("none"))
    }
    async fn list_bundles(
        &self,
        _t: &str,
    ) -> Result<
        Vec<waygate_manifest_store::ManifestBundleSummary>,
        waygate_manifest_store::ManifestError,
    > {
        Ok(vec![])
    }
    async fn get(
        &self,
        _t: &str,
        id: Uuid,
    ) -> Result<waygate_manifest_store::ManifestBundle, waygate_manifest_store::ManifestError> {
        let g = self.bundles.lock().unwrap();
        g.iter()
            .find(|b| b.id == id)
            .cloned()
            .ok_or(waygate_manifest_store::ManifestError::NotFound("id"))
    }
    async fn create_draft(
        &self,
        _t: &str,
        content: &str,
        author: Option<&str>,
    ) -> Result<waygate_manifest_store::ManifestBundle, waygate_manifest_store::ManifestError> {
        let mut g = self.bundles.lock().unwrap();
        let version = g.iter().map(|b| b.version).max().unwrap_or(0) + 1;
        let b = waygate_manifest_store::ManifestBundle {
            id: Uuid::new_v4(),
            tenant_id: waygate_core::TenantId::DEFAULT.to_string(),
            version,
            status: waygate_manifest_store::ManifestStatus::Draft,
            content: content.to_string(),
            content_hash: waygate_manifest_store::content_hash(content),
            author: author.map(str::to_string),
            created_at: OffsetDateTime::UNIX_EPOCH,
            published_at: None,
            published_by: None,
        };
        g.push(b.clone());
        Ok(b)
    }
    async fn publish(
        &self,
        _t: &str,
        id: Uuid,
        publisher: &str,
    ) -> Result<waygate_manifest_store::ManifestBundle, waygate_manifest_store::ManifestError> {
        let mut g = self.bundles.lock().unwrap();
        let b = g
            .iter_mut()
            .find(|b| {
                b.id == id && matches!(b.status, waygate_manifest_store::ManifestStatus::Draft)
            })
            .ok_or(waygate_manifest_store::ManifestError::NotFound("draft"))?;
        b.status = waygate_manifest_store::ManifestStatus::Published;
        b.published_at = Some(OffsetDateTime::UNIX_EPOCH);
        b.published_by = Some(publisher.to_string());
        Ok(b.clone())
    }
    async fn rollback_to(
        &self,
        _t: &str,
        _v: i32,
        _a: &str,
    ) -> Result<waygate_manifest_store::ManifestBundle, waygate_manifest_store::ManifestError> {
        Err(waygate_manifest_store::ManifestError::NotFound("rollback"))
    }
    async fn delete_all_for_tenant(
        &self,
        _t: &str,
    ) -> Result<u64, waygate_manifest_store::ManifestError> {
        Ok(0)
    }
    async fn read_pointer(
        &self,
        _t: &str,
    ) -> Result<
        Option<waygate_manifest_store::ManifestPointer>,
        waygate_manifest_store::ManifestError,
    > {
        Ok(self
            .pointer
            .lock()
            .unwrap()
            .as_ref()
            .map(|h| waygate_manifest_store::ManifestPointer {
                tenant_id: waygate_core::TenantId::DEFAULT.to_string(),
                current_hash: h.clone(),
                updated_at: OffsetDateTime::UNIX_EPOCH,
                updated_by: None,
            }))
    }
    async fn seed_pointer(
        &self,
        _t: &str,
        hash: &str,
    ) -> Result<(), waygate_manifest_store::ManifestError> {
        let mut p = self.pointer.lock().unwrap();
        if p.is_none() {
            *p = Some(hash.to_string());
        }
        Ok(())
    }
    async fn cas_pointer(
        &self,
        _t: &str,
        expected_hash: &str,
        new_hash: &str,
        _actor: &str,
    ) -> Result<waygate_manifest_store::TurnstileOutcome, waygate_manifest_store::ManifestError>
    {
        let mut p = self.pointer.lock().unwrap();
        if p.as_deref() == Some(expected_hash) {
            *p = Some(new_hash.to_string());
            Ok(waygate_manifest_store::TurnstileOutcome::Won)
        } else {
            Ok(waygate_manifest_store::TurnstileOutcome::Lost)
        }
    }

    async fn list_replica_heartbeats(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<waygate_manifest_store::ReplicaHeartbeat>, waygate_manifest_store::ManifestError>
    {
        Ok(self
            .heartbeats
            .lock()
            .unwrap()
            .iter()
            .filter(|heartbeat| heartbeat.tenant_id == tenant_id)
            .cloned()
            .collect())
    }
}
