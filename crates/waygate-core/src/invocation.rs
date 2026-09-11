//! Stable execution hierarchy shared by invocation and evidence surfaces.

use std::num::NonZeroU32;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Identifies one nested tool-call attempt inside a parent execution.
///
/// The parent execution id remains stable for the whole program. Each ordered
/// step owns a stable call id, while `attempt` distinguishes retries of that
/// same call. The read-only runtime emits only attempt one; durable retry and
/// resume reuse this shape rather than introducing a second hierarchy model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct InvocationHierarchy {
    /// Identity shared by every nested call in one program execution.
    pub parent_execution_id: Uuid,
    /// One-based broker-call order within the parent execution.
    #[schema(value_type = u32, minimum = 1)]
    pub step: NonZeroU32,
    /// Stable identity retained when the same call is retried.
    pub call_id: Uuid,
    /// One-based attempt number for the stable call identity.
    #[schema(value_type = u32, minimum = 1)]
    pub attempt: NonZeroU32,
}

impl InvocationHierarchy {
    pub fn new(
        parent_execution_id: Uuid,
        step: NonZeroU32,
        call_id: Uuid,
        attempt: NonZeroU32,
    ) -> Self {
        Self {
            parent_execution_id,
            step,
            call_id,
            attempt,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hierarchy_round_trips_without_losing_typed_identity() {
        let hierarchy = InvocationHierarchy::new(
            Uuid::now_v7(),
            NonZeroU32::new(3).unwrap(),
            Uuid::now_v7(),
            NonZeroU32::new(2).unwrap(),
        );

        let encoded = serde_json::to_value(hierarchy).unwrap();
        assert_eq!(
            serde_json::from_value::<InvocationHierarchy>(encoded).unwrap(),
            hierarchy
        );
    }
}
