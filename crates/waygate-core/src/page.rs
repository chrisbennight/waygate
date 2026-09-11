//! The one set of list-pagination primitives.
//!
//! Before this module, `MAX_LIST_LIMIT` was redefined in nine crates —
//! seven at 500, one at 200, one (as `DEFAULT_PAGE_LIMIT: i64`) at 100 —
//! with doc comments claiming they "mirror" each other, and
//! `fn default_limit()` was redefined ten times across `waygate-admin`
//! handlers (nine at 50, one at 100). The shared default/ceiling now
//! live here; a surface that deliberately needs a different cap keeps a
//! local, explicitly-commented override (today:
//! `waygate-storage::agent_conversations` at 200 and
//! `waygate_dashboard_stores::scim_provisioning_log`'s timestamp-cursor pager at 100).
//! CI blocks new uncommented redefinitions
//! (`scripts/check-shared-pagination-limits.sh`).

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Default page size when a list request doesn't specify `limit`.
pub const DEFAULT_LIST_LIMIT: u32 = 50;

/// Hard ceiling on list page sizes: a `limit` above this clamps down.
pub const MAX_LIST_LIMIT: u32 = 500;

/// [`DEFAULT_LIST_LIMIT`] as a function, for
/// `#[serde(default = "waygate_core::page::default_list_limit")]`.
pub fn default_list_limit() -> u32 {
    DEFAULT_LIST_LIMIT
}

/// [`default_list_limit`] for the surfaces whose limit field is `i64`
/// (cursor-paged endpoints like the audit feed).
pub fn default_list_limit_i64() -> i64 {
    DEFAULT_LIST_LIMIT as i64
}

/// The standard `?limit=&offset=` query-string pair for list endpoints.
#[derive(Debug, Clone, Copy, Default, Deserialize, ToSchema)]
pub struct ListQuery {
    /// Max rows to return; defaults to [`DEFAULT_LIST_LIMIT`], clamped
    /// to the surface's ceiling (usually [`MAX_LIST_LIMIT`]).
    pub limit: Option<u32>,
    /// Rows to skip; defaults to 0.
    pub offset: Option<u32>,
}

impl ListQuery {
    /// Resolve to a concrete `(limit, offset)` under `max`: a missing
    /// limit becomes [`DEFAULT_LIST_LIMIT`] (itself capped by `max`),
    /// `limit=0` becomes 1, anything above `max` clamps down.
    pub fn clamped(&self, max: u32) -> (u32, u32) {
        let limit = self
            .limit
            .unwrap_or(DEFAULT_LIST_LIMIT)
            .clamp(1, max.max(1));
        (limit, self.offset.unwrap_or(0))
    }
}

/// The standard list-response envelope.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Page<T> {
    pub items: Vec<T>,
    /// Total matching rows when the store computes it; `None` when the
    /// surface only knows the current page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    pub limit: u32,
    pub offset: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamped_applies_default_floor_and_ceiling() {
        let table = [
            // (limit, offset, max) -> (expected limit, expected offset)
            (None, None, MAX_LIST_LIMIT, DEFAULT_LIST_LIMIT, 0),
            (Some(0), None, MAX_LIST_LIMIT, 1, 0),
            (Some(10), Some(20), MAX_LIST_LIMIT, 10, 20),
            (Some(9999), None, MAX_LIST_LIMIT, MAX_LIST_LIMIT, 0),
            // A surface with a tighter ceiling clamps the default too.
            (None, None, 25, 25, 0),
        ];
        for (limit, offset, max, want_limit, want_offset) in table {
            let q = ListQuery { limit, offset };
            assert_eq!(
                q.clamped(max),
                (want_limit, want_offset),
                "limit={limit:?} offset={offset:?} max={max}"
            );
        }
    }

    #[test]
    fn page_omits_absent_total_on_the_wire() {
        let page = Page {
            items: vec![1u32],
            total: None,
            limit: 50,
            offset: 0,
        };
        let v = serde_json::to_value(&page).unwrap();
        assert!(v.get("total").is_none());
        assert_eq!(v["items"], serde_json::json!([1]));
    }
}
