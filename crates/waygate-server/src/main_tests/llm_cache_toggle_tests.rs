use super::{llm_cache_row_cap, DEFAULT_LLM_CACHE_MAX_ROWS_PER_TENANT};

// Grammar and reject-at-boot behavior for GATEWAY_LLM_CACHE_ENABLED /
// GATEWAY_LLM_CACHE_SWEEP_SECONDS / GATEWAY_LLM_CACHE_MAX_ROWS_PER_TENANT
// now live in the shared typed readers (`waygate_core::env`, tested there).
// What remains main.rs-owned is the 0-sentinel mapping of the row cap.

#[test]
fn row_cap_zero_is_unlimited_positive_honored() {
    // 0 ⇒ explicitly unbounded by count (TTL + sweep only).
    assert_eq!(llm_cache_row_cap(0), None);
    // A positive value caps the tenant at that many rows.
    assert_eq!(llm_cache_row_cap(500), Some(500));
    // The unset-default stays finite — "unset" must never mean "unlimited";
    // the cap's whole purpose is to bound growth within a TTL window.
    assert_eq!(
        llm_cache_row_cap(DEFAULT_LLM_CACHE_MAX_ROWS_PER_TENANT as u64),
        Some(DEFAULT_LLM_CACHE_MAX_ROWS_PER_TENANT)
    );
}
