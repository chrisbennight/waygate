//! Gateway-wide response delivery configuration shared by dashboard and runtime.

use std::num::NonZeroUsize;
use std::sync::Arc;

use async_trait::async_trait;
use sqlx::{PgPool, Row};

pub const DEFAULT_INLINE_RESPONSE_THRESHOLD_BYTES: NonZeroUsize =
    NonZeroUsize::new(16 * 1024).unwrap();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseSettings {
    pub inline_response_threshold_bytes: NonZeroUsize,
    pub revision: i64,
}

impl Default for ResponseSettings {
    fn default() -> Self {
        Self {
            inline_response_threshold_bytes: DEFAULT_INLINE_RESPONSE_THRESHOLD_BYTES,
            revision: 0,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ResponseSettingsError {
    #[error("response settings database: {0}")]
    Database(#[from] sqlx::Error),
    #[error("response threshold must be a positive byte count representable by the database")]
    InvalidThreshold,
    #[error("response settings changed; reopen Settings before saving")]
    Conflict,
    #[error("saving response settings requires the gateway database")]
    Unavailable,
}

#[async_trait]
pub trait ResponseSettingsStore: Send + Sync + 'static {
    async fn get(&self) -> Result<ResponseSettings, ResponseSettingsError>;
    /// Update only the revision the operator viewed, preventing lost edits.
    async fn update(
        &self,
        expected_revision: i64,
        threshold: NonZeroUsize,
        actor: &str,
    ) -> Result<ResponseSettings, ResponseSettingsError>;
}

pub struct PgResponseSettingsStore {
    pool: PgPool,
}

impl PgResponseSettingsStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn decode(row: sqlx::postgres::PgRow) -> Result<ResponseSettings, ResponseSettingsError> {
    let threshold: i64 = row.try_get("inline_response_threshold_bytes")?;
    Ok(ResponseSettings {
        inline_response_threshold_bytes: usize::try_from(threshold)
            .ok()
            .and_then(NonZeroUsize::new)
            .ok_or(ResponseSettingsError::InvalidThreshold)?,
        revision: row.try_get("revision")?,
    })
}

#[async_trait]
impl ResponseSettingsStore for PgResponseSettingsStore {
    async fn get(&self) -> Result<ResponseSettings, ResponseSettingsError> {
        decode(sqlx::query("SELECT inline_response_threshold_bytes, revision FROM response_delivery_settings WHERE singleton = TRUE")
            .fetch_one(&self.pool).await?)
    }

    async fn update(
        &self,
        expected_revision: i64,
        threshold: NonZeroUsize,
        actor: &str,
    ) -> Result<ResponseSettings, ResponseSettingsError> {
        let threshold =
            i64::try_from(threshold.get()).map_err(|_| ResponseSettingsError::InvalidThreshold)?;
        let row = sqlx::query("UPDATE response_delivery_settings SET inline_response_threshold_bytes = $1, revision = revision + 1, updated_by = $2, updated_at = now() WHERE singleton = TRUE AND revision = $3 RETURNING inline_response_threshold_bytes, revision")
            .bind(threshold).bind(actor).bind(expected_revision)
            .fetch_optional(&self.pool).await?
            .ok_or(ResponseSettingsError::Conflict)?;
        decode(row)
    }
}

/// An environment override is fixed at boot; the stored default is read at
/// admission so every replica observes committed dashboard changes.
pub struct ResponseSettingsService {
    store: Option<Arc<dyn ResponseSettingsStore>>,
    environment_override: Option<NonZeroUsize>,
}

impl ResponseSettingsService {
    pub fn new(
        store: Option<Arc<dyn ResponseSettingsStore>>,
        environment_override: Option<NonZeroUsize>,
    ) -> Self {
        Self {
            store,
            environment_override,
        }
    }

    pub fn writable(&self) -> bool {
        self.store.is_some()
    }

    pub fn environment_override(&self) -> Option<NonZeroUsize> {
        self.environment_override
    }

    pub async fn get(&self) -> Result<ResponseSettings, ResponseSettingsError> {
        match &self.store {
            Some(store) => store.get().await,
            None => Ok(ResponseSettings::default()),
        }
    }

    pub async fn effective_threshold(&self) -> Result<NonZeroUsize, ResponseSettingsError> {
        match self.environment_override {
            Some(value) => Ok(value),
            None => Ok(self.get().await?.inline_response_threshold_bytes),
        }
    }

    pub async fn update(
        &self,
        expected_revision: i64,
        threshold: NonZeroUsize,
        actor: &str,
    ) -> Result<ResponseSettings, ResponseSettingsError> {
        self.store
            .as_ref()
            .ok_or(ResponseSettingsError::Unavailable)?
            .update(expected_revision, threshold, actor)
            .await
    }
}
