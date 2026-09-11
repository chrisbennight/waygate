//! RFC 8414 `/.well-known/oauth-authorization-server` metadata.
//!
//! Served directly from the gateway so MCP clients (Claude Code, Cursor, MCP
//! Inspector) can discover the authorize/token/jwks endpoints on the same
//! host as the resource — no separate IdP hop required.

use axum::extract::State;
use axum::response::Json;
use axum::routing::get;
use axum::Router;
use serde::{Deserialize, Serialize};

use crate::router::AsState;

pub const METADATA_PATH: &str = "/.well-known/oauth-authorization-server";

/// EMA (draft-ietf-oauth-identity-assertion-authz-grant) grant-profile URN,
/// advertised in `authorization_grant_profiles_supported` when EMA is enabled.
pub const ID_JAG_GRANT_PROFILE: &str = "urn:ietf:params:oauth:grant-profile:id-jag";

/// RFC 8414 §2 metadata document. Only the fields we actually need.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    /// EMA: the authorization grant profiles this AS supports
    /// (draft-ietf-oauth-identity-assertion-authz-grant). Populated with the
    /// ID-JAG profile only when EMA advertisement is enabled; omitted from the
    /// JSON otherwise so the working OAuth/API-key discovery is unchanged for
    /// deployments that haven't turned EMA on.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authorization_grant_profiles_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    /// Draft-parecki-oauth-client-id-metadata-document §4 — tells clients
    /// the AS accepts HTTPS URL `client_id`s resolved via CIMD.
    pub client_id_metadata_document_supported: bool,
    /// RFC 9207 §3 — the AS includes an `iss` parameter on token
    /// responses so spec-aware clients can detect AS mix-up attacks
    /// (where a malicious AS returns a token the client then submits to
    /// the legitimate AS). The gateway's `/oauth/token` emits the field;
    /// advertising it here tells clients to look for and validate it.
    pub authorization_response_iss_parameter_supported: bool,
    /// Not RFC 8414 but useful for clients that key off `revocation_endpoint`
    /// — we don't expose one yet, so this is omitted in serialization when
    /// `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
}

impl AuthorizationServerMetadata {
    /// `public_url` is the operator-supplied value; this constructor
    /// trims a trailing slash so the advertised `issuer` matches the
    /// canonical form used by [`AsConfig::issuer`] (and therefore by
    /// every RFC 9207 `iss` emission). RFC 9207 §2.4 mandates exact
    /// string match between metadata `issuer` and received `iss`.
    /// `advertise_ema` is the operator's EMA opt-in folded with "EMA deps are
    /// actually wired" (the handler passes
    /// `state.config.idjag_advertise && state.ema.is_some()`). When true, the
    /// two EMA grant URNs are appended to `grant_types_supported` and the ID-JAG
    /// grant profile is listed — so the AS only advertises grants its
    /// `/oauth/token` handler can actually service.
    pub fn build(public_url: &str, advertise_ema: bool) -> Self {
        let base = public_url.trim_end_matches('/');
        let mut grant_types_supported =
            vec!["authorization_code".to_owned(), "refresh_token".to_owned()];
        let mut authorization_grant_profiles_supported = Vec::new();
        // CIMD v1 public clients authenticate the authorization_code/refresh_token
        // grants with PKCE + `none`. The EMA jwt-bearer *redeem* grant, in
        // contrast, requires confidential-client authentication, so when we
        // advertise that grant we MUST also advertise the auth methods its
        // handler accepts — otherwise a client following the metadata discovers
        // the grant but not how to authenticate to it. These
        // mirror `waygate_as::client_auth::ClientCredentials::extract`:
        // `client_secret` via HTTP Basic or POST body, and `private_key_jwt`.
        let mut token_endpoint_auth_methods_supported = vec!["none".to_owned()];
        if advertise_ema {
            grant_types_supported.push(crate::token::GRANT_TOKEN_EXCHANGE.to_owned());
            grant_types_supported.push(crate::token::GRANT_JWT_BEARER.to_owned());
            authorization_grant_profiles_supported.push(ID_JAG_GRANT_PROFILE.to_owned());
            token_endpoint_auth_methods_supported.extend([
                "client_secret_basic".to_owned(),
                "client_secret_post".to_owned(),
                "private_key_jwt".to_owned(),
            ]);
        }
        Self {
            issuer: base.to_owned(),
            authorization_endpoint: format!("{base}/oauth/authorize"),
            token_endpoint: format!("{base}/oauth/token"),
            jwks_uri: format!("{base}{}", waygate_oidc::JWKS_PATH),
            response_types_supported: vec!["code".into()],
            grant_types_supported,
            authorization_grant_profiles_supported,
            code_challenge_methods_supported: vec!["S256".into()],
            // CIMD v1 public clients (authorization_code/refresh_token) use
            // `none`; the EMA jwt-bearer redeem grant adds the confidential-client
            // methods above when advertised.
            token_endpoint_auth_methods_supported,
            scopes_supported: vec![
                "mcp:invoke".into(),
                "mcp:invoke:high".into(),
                "mcp:read".into(),
                "mcp:admin".into(),
                // HITL: advertise the maker scope so a CIMD client
                // knows it can request mcp:propose from this AS.
                "mcp:propose".into(),
                // Advertise the read-only observability scope so a monitoring
                // client knows it can request mcp:observe (the scope the
                // `gateway-observe.*` read plane checks) from this AS.
                "mcp:observe".into(),
            ],

            client_id_metadata_document_supported: true,
            authorization_response_iss_parameter_supported: true,
            revocation_endpoint: None,
        }
    }
}

pub fn router() -> Router<AsState> {
    Router::new().route(METADATA_PATH, get(handler))
}

async fn handler(State(state): State<AsState>) -> Json<AuthorizationServerMetadata> {
    // Advertise EMA grants only when the operator opted in AND the EMA deps are
    // wired — never advertise a grant `/oauth/token` would reject.
    let advertise_ema = state.config.idjag_advertise && state.ema.is_some();
    Json(AuthorizationServerMetadata::build(
        &state.config.public_url,
        advertise_ema,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_has_expected_shape() {
        let m = AuthorizationServerMetadata::build("https://gateway.example.com/", false);
        assert_eq!(m.issuer, "https://gateway.example.com");
        assert_eq!(
            m.authorization_endpoint,
            "https://gateway.example.com/oauth/authorize"
        );
        assert_eq!(m.token_endpoint, "https://gateway.example.com/oauth/token");
        assert_eq!(
            m.jwks_uri,
            "https://gateway.example.com/.well-known/jwks.json"
        );
        assert_eq!(m.response_types_supported, vec!["code".to_string()]);
        assert_eq!(m.code_challenge_methods_supported, vec!["S256".to_string()]);
        assert_eq!(
            m.token_endpoint_auth_methods_supported,
            vec!["none".to_string()],
        );
        assert!(m.client_id_metadata_document_supported);
        assert!(
            m.authorization_response_iss_parameter_supported,
            "RFC 9207 iss support must be advertised so spec-aware clients \
             validate the iss returned on token responses"
        );
        // The maker scope must be advertised so a CIMD client following
        // the AS metadata can request mcp:propose — otherwise the
        // propose surface is unreachable via the default AS.
        assert!(
            m.scopes_supported.contains(&"mcp:propose".to_string()),
            "mcp:propose must be advertised in scopes_supported",
        );
        // Model step-up (`llm:invoke:high`) is retired — models are not
        // step-up-gated. Guard the retired scope is not re-advertised.
        assert!(
            !m.scopes_supported.contains(&"llm:invoke:high".to_string()),
            "llm:invoke:high is retired and must not be advertised",
        );
        // The read-only observability scope must be advertised so a monitoring
        // client following the AS metadata can request mcp:observe — otherwise
        // the gateway-observe.* read plane is unreachable via the default AS.
        assert!(
            m.scopes_supported.contains(&"mcp:observe".to_string()),
            "mcp:observe must be advertised in scopes_supported",
        );
    }

    #[test]
    fn issuer_matches_canonical_iss_even_with_trailing_slash() {
        // RFC 9207 §2.4 requires byte-identical match between the
        // advertised metadata `issuer` and any received `iss`. The
        // operator may supply `GATEWAY_PUBLIC_URL` with or without a
        // trailing slash; `AsConfig::issuer()` canonicalises (trims),
        // and `AuthorizationServerMetadata::build` does the same. Pin
        // that they produce the same string on both shapes.
        let with_slash = AuthorizationServerMetadata::build("https://mcp.example/", false);
        let without_slash = AuthorizationServerMetadata::build("https://mcp.example", false);
        assert_eq!(with_slash.issuer, "https://mcp.example");
        assert_eq!(without_slash.issuer, "https://mcp.example");
        assert_eq!(with_slash.issuer, without_slash.issuer);
    }

    #[test]
    fn metadata_json_omits_none_revocation() {
        let m = AuthorizationServerMetadata::build("https://gateway.example.com", false);
        let body = serde_json::to_string(&m).unwrap();
        assert!(!body.contains("revocation_endpoint"));
    }

    #[test]
    fn ema_grants_are_omitted_when_not_advertised() {
        // Default posture: EMA off ⇒ discovery is byte-for-byte the pre-EMA
        // OAuth/API-key shape. The grant URNs are absent and the profiles key is
        // omitted from JSON entirely (not an empty array).
        let m = AuthorizationServerMetadata::build("https://mcp.example", false);
        assert_eq!(
            m.grant_types_supported,
            vec![
                "authorization_code".to_string(),
                "refresh_token".to_string()
            ],
        );
        assert!(m.authorization_grant_profiles_supported.is_empty());
        let body = serde_json::to_string(&m).unwrap();
        assert!(
            !body.contains("authorization_grant_profiles_supported"),
            "the profiles key must be omitted when EMA is not advertised",
        );
        assert!(!body.contains("grant-type:token-exchange"));
        assert!(!body.contains("grant-type:jwt-bearer"));
        // Confidential-client auth methods are NOT advertised when EMA is off —
        // the public CIMD path uses `none` only.
        assert_eq!(
            m.token_endpoint_auth_methods_supported,
            vec!["none".to_string()],
        );
    }

    #[test]
    fn ema_grants_are_advertised_when_enabled() {
        // EMA on ⇒ both grant URNs appear in grant_types_supported AND the ID-JAG
        // grant profile is listed, so a spec-aware client discovers the
        // token-exchange (mint) + jwt-bearer (redeem) flows.
        let m = AuthorizationServerMetadata::build("https://mcp.example", true);
        assert!(m
            .grant_types_supported
            .contains(&"urn:ietf:params:oauth:grant-type:token-exchange".to_string()));
        assert!(m
            .grant_types_supported
            .contains(&"urn:ietf:params:oauth:grant-type:jwt-bearer".to_string()));
        assert_eq!(
            m.authorization_grant_profiles_supported,
            vec![ID_JAG_GRANT_PROFILE.to_string()],
        );
        // The base grants remain (EMA is additive, not a replacement).
        assert!(m
            .grant_types_supported
            .contains(&"authorization_code".to_string()));
        // Advertising jwt-bearer (redeem) MUST also advertise the
        // confidential-client auth methods its handler accepts, or the grant
        // isn't serviceable from discovery. These mirror
        // `client_auth::ClientCredentials::extract`.
        for method in [
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
        ] {
            assert!(
                m.token_endpoint_auth_methods_supported
                    .contains(&method.to_string()),
                "advertised jwt-bearer redeem requires advertising auth method {method}",
            );
        }
        // The public CIMD method is still offered for the authorization_code flow.
        assert!(m
            .token_endpoint_auth_methods_supported
            .contains(&"none".to_string()));
    }
}
