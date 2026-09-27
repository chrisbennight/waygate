//! In-memory task-route store shared by protocol contract tests.
use std::{collections::HashMap, sync::Mutex};
use uuid::Uuid;
use waygate_core::store::StoreError;
use waygate_invocation::task_routes::{TaskRoute, TaskRouteStore};

#[derive(Default)]
pub struct InMemoryTaskRouteStore {
    routes: Mutex<HashMap<Uuid, TaskRoute>>,
}

#[async_trait::async_trait]
impl TaskRouteStore for InMemoryTaskRouteStore {
    async fn insert(&self, id: Uuid, route: &TaskRoute) -> Result<(), StoreError> {
        let mut routes = self.routes.lock().unwrap();
        match routes.entry(id) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(route.clone());
                Ok(())
            }
            std::collections::hash_map::Entry::Occupied(_) => Err(StoreError::Conflict),
        }
    }

    async fn get(&self, id: Uuid, tenant: &str) -> Result<Option<TaskRoute>, StoreError> {
        Ok(self
            .routes
            .lock()
            .unwrap()
            .get(&id)
            .filter(|r| {
                r.tenant == tenant && r.exp > time::OffsetDateTime::now_utc().unix_timestamp()
            })
            .cloned())
    }
}
