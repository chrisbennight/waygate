//! `/.well-known/oauth-protected-resource` — RFC 9728 metadata that advertises
//! which authorization server(s) issue tokens for this resource. Spec-aware
//! MCP clients read this on a `401 WWW-Authenticate` to discover Authentik.

use axum::response::Json;
use axum::routing::get;
use axum::Router;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scopes_supported: Vec<String>,
    pub bearer_methods_supported: Vec<String>,
}

impl ResourceMetadata {
    pub fn new(resource: impl Into<String>, issuer: impl Into<String>) -> Self {
        Self::with_issuers(resource, vec![issuer.into()])
    }

    /// Build metadata with an explicit list of authorization servers. When the
    /// gateway is its own AS (CIMD mode), this is a single-element vec
    /// pointing at the gateway itself; when we fell back to Authentik it was
    /// the IdP's issuer. Having both callers routed through one constructor
    /// keeps the `scopes_supported` / `bearer_methods_supported` defaults in
    /// one place.
    pub fn with_issuers(resource: impl Into<String>, authorization_servers: Vec<String>) -> Self {
        Self {
            resource: resource.into(),
            authorization_servers,
            // Advertise the `mcp:invoke:high` step-up scope so spec-aware clients
            // can re-authorize after a gateway-issued `insufficient_scope`
            // response without guessing the scope name.
            scopes_supported: vec![
                "mcp:invoke".into(),
                "mcp:invoke:high".into(),
                "mcp:read".into(),
                "mcp:admin".into(),
                // The HITL maker scope so discovery surfaces tell
                // automated callers the propose surface exists.
                "mcp:propose".into(),
                // The read-only observability scope so a spec-aware client
                // validating requested scopes against this RFC 9728 metadata
                // can discover and request mcp:observe (the AS metadata
                // advertises it too).
                "mcp:observe".into(),
                // SCIM scopes so discovery surfaces tell
                // IdP / API-key issuers about the SCIM
                // endpoints.
                "scim:read".into(),
                "scim:write".into(),
            ],
            bearer_methods_supported: vec!["header".into()],
        }
    }

    /// Canonical well-known URL path for this metadata.
    pub const PATH: &'static str = "/.well-known/oauth-protected-resource";
}

/// Router that serves the resource metadata as JSON.
pub fn router<S>(meta: ResourceMetadata) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new().route(
        ResourceMetadata::PATH,
        get(move || async move { Json(meta) }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_advertise_the_retired_llm_step_up_scope() {
        // Model step-up (`llm:invoke:high`) is retired — models are not
        // step-up-gated. Guard that the retired scope is not re-advertised, and
        // that the surviving `mcp:invoke:high` step-up scope still is.
        let meta = ResourceMetadata::with_issuers(
            "https://mcp.example.test",
            vec!["https://mcp.example.test".into()],
        );
        assert!(
            !meta
                .scopes_supported
                .contains(&"llm:invoke:high".to_string()),
            "llm:invoke:high is retired and must not be advertised",
        );
        assert!(
            meta.scopes_supported
                .contains(&"mcp:invoke:high".to_string()),
            "the mcp:invoke:high step-up scope is still advertised",
        );
    }

    #[test]
    fn advertises_the_observe_scope() {
        // The RFC 9728 protected-resource metadata must advertise mcp:observe
        // (in lock-step with the RFC 8414 AS metadata) so a spec-aware MCP
        // client validating requested scopes against it can discover and
        // request the gateway-observe.* read-plane scope.
        let meta = ResourceMetadata::with_issuers(
            "https://mcp.example.test",
            vec!["https://mcp.example.test".into()],
        );
        assert!(
            meta.scopes_supported.contains(&"mcp:observe".to_string()),
            "mcp:observe must be advertised in protected-resource scopes_supported",
        );
    }
}
