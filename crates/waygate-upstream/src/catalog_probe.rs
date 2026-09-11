use waygate_oidc::{AuthMethod, Principal};

use crate::IdentityContext;

pub(crate) fn catalog_probe_identity(server: &str, groups: &[String]) -> IdentityContext {
    IdentityContext {
        principal: Principal {
            sub: "mcp-tool-search-gateway:catalog-probe".into(),
            email: None,
            groups: groups.to_vec(),
            issuer: "urn:mcp-tool-search-gateway:catalog-probe".into(),
            scopes: vec![],
            tenant: Default::default(),
            auth_method: AuthMethod::PeerAssertion,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        },
        audience: server.to_owned(),
        exchange: None,
        stored_upstream_subject_token: None,
        exchanged_bearer: None,
        tier_c_audience: None,
    }
}
