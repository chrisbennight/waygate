//! waygate-server implementations of the EMA injection seams.
//!
//! `waygate-as` defines [`SubjectTokenResolver`] / [`CrossAppPolicy`]; this
//! module wires them to the composition root's bearer validators and Cedar
//! gate, then `main.rs` injects them via [`waygate_as::EmaDeps`] at
//! `build_router` time. See `docs/agents/ema.md`.

use std::sync::Arc;

use async_trait::async_trait;

use waygate_as::{
    CrossAppDenied, CrossAppPolicy, ResolvedSubject, SubjectResolveError, SubjectTokenResolver,
};
use waygate_authz::cross_app_facts;
use waygate_mcp::authz::{AuthzVerdict, SharedAuthz};
use waygate_oidc::{BearerValidator, IdTokenValidator, Principal};

/// RFC 8693 subject-token-type URNs the resolver accepts.
const TT_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
const TT_ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";

/// Resolves an RFC 8693 `subject_token` to a [`Principal`]:
/// a gateway-minted access token (validated against the gateway's own
/// preloaded JWKS — the primary EMA path, where the client SSO'd to the
/// gateway via CIMD), or an Authentik id_token. Any other token type is
/// rejected.
pub struct ServerSubjectResolver {
    access: Arc<BearerValidator>,
    id_token: Arc<IdTokenValidator>,
}

impl ServerSubjectResolver {
    pub fn new(access: Arc<BearerValidator>, id_token: Arc<IdTokenValidator>) -> Self {
        Self { access, id_token }
    }
}

#[async_trait]
impl SubjectTokenResolver for ServerSubjectResolver {
    async fn resolve(
        &self,
        subject_token_type: &str,
        subject_token: &str,
    ) -> Result<ResolvedSubject, SubjectResolveError> {
        // Surface the *authenticated* client (the subject token's own
        // client_id / azp) alongside the principal so the handler can bind it
        // into the ID-JAG and reject a mismatching caller-supplied client_id.
        let (principal, client_id) = match subject_token_type {
            TT_ACCESS_TOKEN => self
                .access
                .validate_with_client_id(subject_token)
                .await
                .map_err(|_| SubjectResolveError)?,
            TT_ID_TOKEN => self
                .id_token
                .validate_with_client_id(subject_token)
                .await
                .map_err(|_| SubjectResolveError)?,
            _ => return Err(SubjectResolveError),
        };
        Ok(ResolvedSubject {
            principal,
            client_id,
        })
    }
}

/// Cross-app policy backed by the SAME Cedar gate the `/mcp` invocation
/// path uses — so an EMA grant obeys the same policy stack (including any
/// overlays) as a direct tool call. Evaluates the `GrantCrossAppAccess`
/// action via [`cross_app_facts`] (with `client_id` in `context`).
/// Fail-closed: anything but a clean `Allow` denies.
pub struct CedarCrossAppPolicy {
    authz: SharedAuthz,
}

impl CedarCrossAppPolicy {
    pub fn new(authz: SharedAuthz) -> Self {
        Self { authz }
    }
}

#[async_trait]
impl CrossAppPolicy for CedarCrossAppPolicy {
    async fn authorize(
        &self,
        principal: &Principal,
        client_id: &str,
        resource: &str,
    ) -> Result<(), CrossAppDenied> {
        let facts = cross_app_facts(principal, client_id, resource);
        // `authorize_tool_call` is the gate's generic Facts entry point —
        // it evaluates whatever action the Facts carry (here
        // GrantCrossAppAccess), not just tool calls.
        match self.authz.authorize_tool_call(&facts).await {
            // `Allow` is a struct variant carrying the fired permit ids for
            // audit; the cross-app check only cares allow vs. not, so it
            // ignores them.
            AuthzVerdict::Allow { .. } => Ok(()),
            _ => Err(CrossAppDenied),
        }
    }
}
