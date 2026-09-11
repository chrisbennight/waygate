//! Gateway-as-Authorization-Server.
//!
//! Turns the gateway into a lightweight OAuth 2.1 AS that fronts Authentik.
//! MCP clients authenticate by serving a CIMD document
//! (draft-parecki-oauth-client-id-metadata-document) — no per-client
//! pre-registration needed.
//!
//! Public surface:
//! * [`AsConfig`] — runtime configuration
//! * [`router`] — axum router to nest under the gateway
//! * [`metadata`] — `/.well-known/oauth-authorization-server` handler
//!
//! See the workspace plan for the architecture (token-factory pattern,
//! dual PKCE, upstream-token encryption).

mod audit;
pub mod authorize;
pub mod callback;
pub mod cimd;
pub mod cimd_dev_host;
pub mod client_auth;
pub mod clients;
pub mod config;
pub mod consent;
pub mod consent_pending;
pub mod consent_screen;
pub use waygate_oidc::upstream_crypto as crypto;
pub mod ema;
pub mod metadata;
pub mod reencrypt_sweeper;
pub mod router;
pub mod session_refresh;
pub mod sessions;
pub mod store;
pub mod token;

pub use client_auth::{authenticate_client, ClientAuthError, ClientCredentials};
pub use clients::{
    ConfidentialClient, ConfidentialClientError, ConfidentialClientStore,
    PgConfidentialClientStore, SharedConfidentialClientStore,
};
pub use config::AsConfig;
pub use crypto::UpstreamCrypto;
pub use ema::{
    CrossAppDenied, CrossAppPolicy, EmaDeps, ResolvedSubject, SubjectResolveError,
    SubjectTokenResolver,
};
pub use router::{build_router, AsState};
