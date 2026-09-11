//! Bearer-validate-time hook for enriching a [`Principal`] with
//! attributes resolved from external sources (SCIM, attribute APIs,
//! profile stores, …).
//!
//! ## Why this lives here
//!
//! [`BearerValidator`](crate::BearerValidator) and the API-key
//! validator produce a [`Principal`] from primary credentials only —
//! JWT claims and `api_keys` columns. Anything beyond that (SCIM
//! group memberships, custom attributes provisioned by an external
//! IdP) lives in a different storage layer (`scim_users`,
//! `scim_user_groups`, etc., owned by `waygate-scim`).
//!
//! Plumbing those lookups directly into the validators would couple
//! `waygate-oidc` to a specific attribute source. The enricher trait
//! flips the dependency: `waygate-oidc` defines the seam; concrete
//! enrichers live in the crates that own the attribute storage and
//! depend on this crate for the [`Principal`] type.
//!
//! ## Best-effort contract
//!
//! Enrichment is a side-channel lookup, not a validation step. A
//! database outage, a missing SCIM row, or a transient timeout must
//! NOT block the request — the enricher returns the original
//! principal unchanged and logs a `tracing::warn!`. Hard-fail
//! behaviour would mean every gateway is unavailable whenever the
//! SCIM database hiccups, which is the opposite of what an attribute
//! enrichment layer should do.
//!
//! Errors that *should* block the request (revoked principal,
//! tenant-mismatch attack, …) belong in the validator path, not the
//! enricher — the enricher only adds context.

use async_trait::async_trait;

use crate::Principal;

/// Hook invoked by [`BearerLayer`](crate::BearerLayer) after a
/// validator returns an authenticated principal. Implementations
/// merge additional attributes (e.g. SCIM-resolved groups, custom
/// JSONB attrs) into the principal.
///
/// Implementations MUST be best-effort: on internal failure return
/// `principal` unchanged (log via `tracing` if warranted). Returning
/// a poisoned or partially-enriched principal is acceptable only if
/// the partial state cannot mislead authorization — when in doubt,
/// return the original.
#[async_trait]
pub trait PrincipalEnricher: Send + Sync {
    async fn enrich(&self, principal: Principal) -> Principal;
}
