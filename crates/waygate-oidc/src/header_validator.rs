//! Object-safe abstraction over "thing that turns an Authorization header
//! into a [`Principal`]".
//!
//! The middleware (`crate::middleware`) iterates a chain of validators on
//! every request — JWT-backed for OAuth tokens, table-lookup-backed for
//! static API keys, potentially more later. This trait is the contract that
//! lets a single `Vec<Arc<dyn HeaderValidator>>` hold both.
//!
//! Implementors must return [`ValidationError::is_client_error() == true`]
//! when *this validator* doesn't recognise the token format (so the
//! middleware can fall through to the next validator in the chain) and
//! `false` only when the validator's own infrastructure is broken (DB
//! unreachable, JWKS fetch failing). The middleware uses that distinction
//! to decide between 401 (some validator could have accepted) vs 503
//! (none could even try).

use async_trait::async_trait;

use crate::validator::ValidationError;
use crate::Principal;

/// A validator that turns an `Authorization` header value into a [`Principal`].
///
/// Implementations live next to the storage they validate against —
/// [`crate::BearerValidator`] for JWTs in `waygate-oidc`, `ApiKeyValidator`
/// for static keys in `waygate-apikeys`.
#[async_trait]
pub trait HeaderValidator: Send + Sync + 'static {
    /// Returns `Ok(principal)` if this validator recognised and accepted
    /// the header. Returns `Err(_)` otherwise — see the module docs for
    /// the client-error vs infra-error contract.
    async fn validate_header(&self, header: &str) -> Result<Principal, ValidationError>;
}
