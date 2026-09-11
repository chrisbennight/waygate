//! Static API keys for headless callers (Codex, CI, scripts).
//!
//! Validates `Authorization: Bearer mcpgw_<secret>` against the `api_keys`
//! table and produces a [`waygate_oidc::Principal`] with
//! [`AuthMethod::ApiKey`](waygate_oidc::AuthMethod::ApiKey). Hot path is
//! prefix-indexed lookup + argon2id `verify`, cached for a short TTL
//! (default 60s) so revocation propagates quickly.
//!
//! Mint / list / revoke surfaces live on the dashboard side
//! (`waygate-admin::api_keys`).
//!
//! Public surface:
//! * [`ApiKeyValidator`] — the [`waygate_oidc::HeaderValidator`] impl.
//! * [`ApiKeyStore`] — sqlx-backed table accessor.
//! * [`token`] — `mcpgw_…` parsing and minting helpers.

pub mod group_store;
pub mod profiles;
pub mod scope_store;
pub mod store;
pub mod token;
pub mod validator;

pub use group_store::{
    GroupStore, GroupStoreError, GroupView, LocalGroupDeleteTarget, PgGroupStore,
};
pub use profiles::{MintViolation, PgProfileStore, Profile, ProfileStore, ProfileStoreError};
pub use scope_store::{
    LocalScopeDeleteTarget, PgScopeStore, ScopeStore, ScopeStoreError, ScopeView,
};
pub use store::{ApiKeyRow, ApiKeyStore, StoreError, UsageBucket};
pub use token::{MintedKey, ParsedToken, TokenError, KEY_PREFIX_LEN, SECRET_LEN, TOKEN_LITERAL};
pub use validator::{ApiKeyValidator, ValidatorConfig};
