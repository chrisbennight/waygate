//! Enterprise-Managed Authorization (EMA) injection seams.
//!
//! The token-exchange endpoint that mints ID-JAGs lives in
//! [`crate::token`], but its two side dependencies — resolving the RFC
//! 8693 `subject_token` to a [`Principal`], and the cross-app policy
//! decision — are owned by `waygate-server` (which holds the bearer
//! validator chain and the Cedar gate). waygate-as defines the traits;
//! `waygate-server` provides the impls and injects them via [`EmaDeps`]
//! at [`crate::build_router`] time. This keeps waygate-as decoupled from
//! `waygate-authz` and the validator stack.

use std::sync::Arc;

use async_trait::async_trait;
use waygate_oidc::{Principal, PrincipalEnricher};

/// The authenticated subject behind an RFC 8693 `subject_token`: the
/// [`Principal`] plus the `client_id` the token itself was issued to.
///
/// The `client_id` is the **authenticated** client — read from the subject
/// token's own claims (a gateway access token's `client_id`, or an id_token's
/// `azp`), never from a caller-supplied form field. The EMA handler binds
/// *this* value into the minted ID-JAG and rejects a request whose form
/// `client_id` disagrees, so a caller cannot mint an assertion bound to a
/// client it did not authenticate as. `None` ⇒ the token carries no client
/// binding (the handler then refuses to mint).
pub struct ResolvedSubject {
    pub principal: Principal,
    pub client_id: Option<String>,
}

/// Resolve an RFC 8693 `subject_token` (+ `subject_token_type`) to the
/// authenticated [`ResolvedSubject`]. The `waygate-server` impl validates a
/// gateway-minted access token (`urn:ietf:params:oauth:token-type:access_token`)
/// or an Authentik id_token (`…:id_token`).
#[async_trait]
pub trait SubjectTokenResolver: Send + Sync {
    async fn resolve(
        &self,
        subject_token_type: &str,
        subject_token: &str,
    ) -> Result<ResolvedSubject, SubjectResolveError>;
}

/// Opaque resolve failure — the handler maps it to `invalid_grant`
/// without telling the caller why (no token-introspection oracle).
#[derive(Debug)]
pub struct SubjectResolveError;

/// The EMA cross-app policy decision: may `principal`, acting through
/// `client_id`, obtain an ID-JAG (cross-app access grant) for `resource`?
/// The `waygate-server` impl evaluates the Cedar `GrantCrossAppAccess`
/// action with `client_id` available as `context.client_id`.
#[async_trait]
pub trait CrossAppPolicy: Send + Sync {
    async fn authorize(
        &self,
        principal: &Principal,
        client_id: &str,
        resource: &str,
    ) -> Result<(), CrossAppDenied>;
}

/// Opaque policy denial — the handler maps it to `access_denied`.
#[derive(Debug)]
pub struct CrossAppDenied;

/// Runtime dependencies for the EMA endpoints, injected at
/// [`crate::build_router`] time. `Some(_)` ⇒ EMA is enabled; `None` ⇒ both the
/// token-exchange (mint) and `jwt-bearer` (redeem) grants at `/oauth/token`
/// return `unsupported_grant_type`. A single `GATEWAY_AS_IDJAG_ENABLED` flag
/// turns on both directions.
///
/// Cheap to clone (every field is `Arc`-wrapped) — [`crate::AsState`]
/// holds it and is itself `Clone`.
#[derive(Clone)]
pub struct EmaDeps {
    pub subject_resolver: Arc<dyn SubjectTokenResolver>,
    pub cross_app_policy: Arc<dyn CrossAppPolicy>,
    /// The same chained enricher the bearer middleware uses, so the
    /// minted ID-JAG's authorization is gated on SCIM-authoritative
    /// facts (groups/active) rather than the subject token's claims.
    pub enricher: Option<Arc<dyn PrincipalEnricher>>,
    /// JWKS the Resource-AS redeem path (`jwt-bearer`) verifies a *self-issued*
    /// ID-JAG's signature against — the gateway's own keyring for homelab
    /// self-redemption. `None` ⇒ the redeem grant returns
    /// `unsupported_grant_type` even when mint is enabled. Peer-issued ID-JAGs
    /// are verified against `peer_jwks` instead (EMA).
    pub verifier: Option<Arc<waygate_oidc::JwksProvider>>,
    /// Confidential-client registry the redeem path authenticates the redeeming
    /// client against (draft §4.4 / §9.1 — confidential clients only). `None` ⇒
    /// the redeem grant returns `unsupported_grant_type`.
    pub client_store: Option<crate::clients::SharedConfidentialClientStore>,
    /// EMA (Tier-C): peer JWKS cache the redeem path resolves a
    /// *peer*-minted ID-JAG's signing keys against (routed by the assertion's
    /// `iss`). `None` ⇒ only self-issued ID-JAGs (verified against `verifier`)
    /// are redeemable; a peer-issued assertion is rejected. For a peer
    /// redemption the minted token's tenant comes from the peer's
    /// `federated_peers` record in this cache, never the assertion's `tenant`
    /// claim — the receiving gateway decides which of its tenants a peer's calls
    /// land in (see `docs/agents/federation.md`).
    pub peer_jwks: Option<waygate_federation::jwks::SharedPeerJwksCache>,
}
