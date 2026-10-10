//! Isolated response-settings store for dashboard and runtime contract tests.

use async_trait::async_trait;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use waygate_dashboard_stores::response_settings::{
    ResponseSettings, ResponseSettingsError, ResponseSettingsStore,
};

#[derive(Default)]
pub struct InMemoryResponseSettingsStore {
    settings: Mutex<ResponseSettings>,
}

#[async_trait]
impl ResponseSettingsStore for InMemoryResponseSettingsStore {
    async fn get(&self) -> Result<ResponseSettings, ResponseSettingsError> {
        Ok(*self.settings.lock().unwrap())
    }

    async fn update(
        &self,
        expected_revision: i64,
        threshold: NonZeroUsize,
        _actor: &str,
    ) -> Result<ResponseSettings, ResponseSettingsError> {
        if i64::try_from(threshold.get()).is_err() {
            return Err(ResponseSettingsError::InvalidThreshold);
        }
        let mut current = self.settings.lock().unwrap();
        if current.revision != expected_revision {
            return Err(ResponseSettingsError::Conflict);
        }
        *current = ResponseSettings {
            inline_response_threshold_bytes: threshold,
            revision: current.revision + 1,
        };
        Ok(*current)
    }
}
