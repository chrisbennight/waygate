//! Scope enforcement for the admin API.
//!
//! Every route is gated by an axum `from_fn` layer that pulls the
//! [`Principal`] out of request extensions (put there by the bearer
//! middleware in `waygate-oidc`) and rejects calls that lack the required
//! scope. We deliberately *don't* trust the principal to be present — dev
//! mode without auth still stamps a synthetic dev principal, so the only way
//! to reach a handler without a principal is a misconfigured router.

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

use waygate_oidc::{AuthMethod, Principal, Scope};

use crate::error::ApiError;

/// Require `scope` on the request's principal, else 401/403. Use in an
/// axum `middleware::from_fn` layer wrapping the routes being protected.
///
/// Defense in depth: refuse the admin / SCIM-write scopes for
/// [`AuthMethod::PeerAssertion`] principals BEFORE the scope check,
/// regardless of what the peer-asserted JWT claimed. `PeerJwtValidator` already
/// strips those scopes at validation, so a well-formed peer
/// assertion never carries them; this is the belt-and-
/// suspenders layer so a future bug in the validator's filter
/// (or a new federation slice that bypasses the filter) can't
/// silently turn a registered peer into a tenant admin.
/// Federated peers are NOT operators of this gateway by
/// design — that's the operator's job on the OTHER end of
/// the federation.
pub async fn require_scope(scope: Scope, req: Request, next: Next) -> Response {
    let principal = req.extensions().get::<Principal>().cloned();
    match principal {
        None => ApiError::Unauthorized("no principal on request").into_response_owned(),
        Some(p) if !peer_assertion_permits(&p, scope) => ApiError::Forbidden(
            "peer-asserted principals may not reach admin, scim:write, or propose",
        )
        .into_response_owned(),
        Some(p) if p.has_scope(scope.as_str()) => next.run(req).await,
        Some(_) => ApiError::Forbidden("missing required scope").into_response_owned(),
    }
}

/// Returns `false` when the request must be rejected on
/// auth-method grounds BEFORE scope is consulted. Today the
/// rule is "peer assertions cannot touch admin or scim:write
/// surfaces under any circumstances." See `require_scope`
/// for the rationale.
fn peer_assertion_permits(principal: &Principal, scope: Scope) -> bool {
    if principal.auth_method != AuthMethod::PeerAssertion {
        return true;
    }
    // Peers are not operators OR makers of this gateway. The
    // PeerJwtValidator strips admin/scim:write at validation; mcp:propose
    // is new and unknown to that filter, so block it here as the
    // belt-and-suspenders layer (same rationale as the admin block).
    !matches!(
        scope,
        Scope::McpAdmin | Scope::ScimWrite | Scope::McpPropose
    )
}

/// Same as [`require_scope`] but for `mcp:read`. Shortcut so router wiring
/// reads cleanly.
pub async fn require_read(req: Request, next: Next) -> Response {
    require_scope(Scope::McpRead, req, next).await
}

/// Same as [`require_scope`] but for `mcp:admin`.
pub async fn require_admin(req: Request, next: Next) -> Response {
    require_scope(Scope::McpAdmin, req, next).await
}

/// Read-only observability gate: `mcp:observe`, with `mcp:admin` satisfying it
/// too (operators can read). A peer-asserted principal is refused even with the
/// scope, mirroring the MCP `gateway-observe.*` built-ins — simulation /
/// diagnostics are gateway-local, and a federated peer carries its own operator
/// on the far side of the federation. (`mcp:observe` is otherwise peer-safe —
/// deliberately absent from the validator's strip list — so this is the
/// surface-level refusal, not a token-level one.)
///
/// Cannot route through [`require_scope`] because that gate is single-scope;
/// the observe surface accepts EITHER `mcp:observe` or `mcp:admin`.
pub async fn require_observe(req: Request, next: Next) -> Response {
    let principal = req.extensions().get::<Principal>().cloned();
    match principal {
        None => ApiError::Unauthorized("no principal on request").into_response_owned(),
        Some(p) if p.auth_method == AuthMethod::PeerAssertion => {
            ApiError::Forbidden("peer-asserted principals may not reach the observe surface")
                .into_response_owned()
        }
        Some(p)
            if p.has_scope(Scope::McpObserve.as_str()) || p.has_scope(Scope::McpAdmin.as_str()) =>
        {
            next.run(req).await
        }
        Some(_) => {
            ApiError::Forbidden("missing required scope (mcp:observe)").into_response_owned()
        }
    }
}

/// `mcp:propose` gate for the change-request maker surface
/// (`POST/GET /api/v1/admin/change_requests`). Lets an
/// automated caller queue + poll a control-plane change without holding
/// `mcp:admin`; the human approves in the dashboard.
pub async fn require_propose(req: Request, next: Next) -> Response {
    require_scope(Scope::McpPropose, req, next).await
}

/// `scim:read` gate for SCIM GETs.
/// Lower-privilege than `scim:write` so an observability
/// tool pulling user lists doesn't gain provisioning
/// rights.
pub async fn require_scim_read(req: Request, next: Next) -> Response {
    require_scope(Scope::ScimRead, req, next).await
}

/// `scim:write` gate for SCIM mutations
/// (POST/PUT/DELETE).
pub async fn require_scim_write(req: Request, next: Next) -> Response {
    require_scope(Scope::ScimWrite, req, next).await
}

/// In-handler version of [`require_admin`] for routes that need scope
/// gating mid-handler (e.g. dashboard POST handlers using `Extension<Principal>`
/// rather than a `from_fn` layer). Returns `Err(_)` with the same
/// 401/403 shape the layer version would.
pub fn require_admin_extension(p: Option<&Principal>) -> Result<(), ApiError> {
    match p {
        None => Err(ApiError::Unauthorized("no principal on request")),
        // Same defense-in-depth refusal as `require_scope` — peer-asserted
        // principals can't reach admin even if a future bug
        // somehow lets `mcp:admin` through the validator's
        // scope filter.
        Some(p) if p.auth_method == AuthMethod::PeerAssertion => Err(ApiError::Forbidden(
            "peer-asserted principals may not reach admin",
        )),
        Some(p) if p.has_scope(Scope::McpAdmin.as_str()) => Ok(()),
        Some(_) => Err(ApiError::Forbidden("missing required scope")),
    }
}

/// Helper so scope middleware can convert `ApiError` into an owned `Response`
/// without the `?` machinery from the handler macros.
impl ApiError {
    pub(crate) fn into_response_owned(self) -> Response {
        axum::response::IntoResponse::into_response(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use waygate_core::TenantId;

    fn peer_principal_with_admin_scope() -> Principal {
        Principal {
            sub: "peer-attestation".into(),
            email: None,
            groups: vec![],
            issuer: "https://peer.example/".into(),
            scopes: vec!["mcp:admin".into()],
            tenant: TenantId::default(),
            auth_method: AuthMethod::PeerAssertion,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        }
    }

    fn oauth_principal_with_admin_scope() -> Principal {
        Principal {
            auth_method: AuthMethod::Oauth,
            ..peer_principal_with_admin_scope()
        }
    }

    #[test]
    fn peer_assertion_permits_blocks_admin() {
        let p = peer_principal_with_admin_scope();
        assert!(!peer_assertion_permits(&p, Scope::McpAdmin));
        assert!(!peer_assertion_permits(&p, Scope::ScimWrite));
        assert!(!peer_assertion_permits(&p, Scope::McpPropose));
        // mcp:invoke and scim:read are still allowed.
        assert!(peer_assertion_permits(&p, Scope::McpInvoke));
        assert!(peer_assertion_permits(&p, Scope::McpRead));
        assert!(peer_assertion_permits(&p, Scope::ScimRead));
    }

    #[test]
    fn peer_assertion_permits_allows_oauth_admin() {
        // Sanity: the deny only fires for PeerAssertion. OAuth
        // and ApiKey principals still pass the auth-method
        // gate and proceed to the regular scope check.
        let p = oauth_principal_with_admin_scope();
        assert!(peer_assertion_permits(&p, Scope::McpAdmin));
        assert!(peer_assertion_permits(&p, Scope::ScimWrite));
    }

    #[test]
    fn require_admin_extension_blocks_peer_assertion() {
        let p = peer_principal_with_admin_scope();
        let err = require_admin_extension(Some(&p)).unwrap_err();
        match err {
            ApiError::Forbidden(msg) => assert!(
                msg.contains("peer-asserted"),
                "error must name the peer-assertion deny: {msg}",
            ),
            other => panic!("expected Forbidden, got {other:?}"),
        }
    }

    #[test]
    fn require_admin_extension_allows_oauth_admin() {
        let p = oauth_principal_with_admin_scope();
        require_admin_extension(Some(&p)).expect("OAuth admin must still pass");
    }
}
