//! Minimal ID-token validator for the dashboard auth flow.
//!
//! The existing [`BearerValidator`](crate::BearerValidator) validates access
//! tokens with audience = the gateway's canonical URL. ID tokens have a
//! different audience (the OAuth client_id) and slightly different claim
//! requirements (per OpenID Connect Core §3.1.3.7), so we keep the two
//! validation paths separate rather than plumbing a mode switch through the
//! hot path.

use std::sync::Arc;

use jsonwebtoken::{decode, decode_header, Algorithm, Validation};
use serde::Deserialize;
use thiserror::Error;

use crate::jwks::{JwksError, JwksProvider};
use crate::Principal;

#[derive(Debug, Error)]
pub enum IdTokenError {
    #[error("token header missing `kid`")]
    MissingKid,
    #[error("unsupported algorithm {0:?}")]
    UnsupportedAlg(Algorithm),
    #[error("jwt: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("jwks: {0}")]
    Jwks(#[from] JwksError),
}

#[derive(Debug, Deserialize)]
struct IdClaims {
    sub: String,
    iss: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
    /// OIDC allows `aud` to be a string OR a string array. Serde's
    /// untagged enum handles both without a custom deserializer. For the EMA
    /// resolver a single-valued `aud` is the client the ID token was issued
    /// for — the fallback client binding when `azp` is absent (per OIDC Core
    /// `azp` is only required for the multi-audience case). See
    /// [`id_token_client`].
    aud: AudClaim,
    /// OIDC permits multiple scopes here or not at all; whatever we get
    /// simply passes through so authz middleware can see it.
    #[serde(default)]
    scope: Option<String>,
    /// OIDC "authorized party" — the client the ID token was issued for.
    /// Surfaced via [`IdTokenValidator::validate_with_client_id`] so the EMA
    /// token-exchange resolver can bind the authenticated client. `None` when
    /// the IdP doesn't emit `azp`.
    #[serde(default)]
    azp: Option<String>,
    /// Time at which the IdP authenticated the operator. Approval-factor
    /// enforcement uses this signed claim to reject stale authentication
    /// assertions rather than treating a long-lived dashboard cookie as a
    /// fresh gesture.
    #[serde(default)]
    auth_time: Option<i64>,
    /// Authentication methods used by the IdP (OIDC `amr`). Kept separate
    /// from [`Principal`] because only the human dashboard session consumes
    /// this assurance evidence.
    #[serde(default)]
    amr: Vec<String>,
    /// Authentication Context Class Reference selected by the IdP. Retained
    /// as signed context for provider-specific AMR normalization; the gateway
    /// does not compare it with a requested MFA class.
    #[serde(default)]
    acr: Option<String>,
    /// Hard-coding `tenant = default` on the dashboard ID-token
    /// path would mean /admin enforced only the default tenant's
    /// lifecycle — a suspended non-default tenant could still hit
    /// the dashboard. So the JWT `tenant` claim is plumbed through
    /// the same way the access-token validator does it (see
    /// `parse_tenant_claim` in `validator.rs`).
    /// Falls back to default on missing/malformed
    /// claim (same fallback as access-token path, with the same
    /// security rationale — better to land in the default bucket
    /// where the resolver will still enforce status, than to skip
    /// enforcement entirely on a typo).
    #[serde(default)]
    tenant: Option<serde_json::Value>,
}

/// Signed authentication-assurance claims from a validated dashboard ID
/// token. They are intentionally not added to [`Principal`]: bearer/API-key
/// authorization does not consume them, while the encrypted dashboard
/// session needs them to enforce fresh approval factors.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdTokenAssurance {
    pub auth_time: Option<i64>,
    pub amr: Vec<String>,
    pub acr: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
// `One`'s value is read by `id_token_client` (the single-audience client
// fallback); `Many`'s vec is only used by jsonwebtoken's own aud check, so keep
// dead-code silenced for that variant's field.
#[allow(dead_code)]
enum AudClaim {
    One(String),
    Many(Vec<String>),
}

/// The client an ID token was issued for, for EMA subject-token binding:
/// `azp` (OIDC "authorized party") when present, otherwise a single-valued
/// `aud` (which, for a standard single-audience ID token, *is* the client).
/// A multi-valued `aud` with no `azp` is ambiguous → `None` (fail-closed; the
/// handler then refuses to mint), matching OIDC Core's rule that `azp` is
/// required precisely in the multi-audience case.
fn id_token_client(azp: Option<&str>, aud: &AudClaim) -> Option<String> {
    azp.map(str::to_owned).or_else(|| match aud {
        AudClaim::One(s) => Some(s.clone()),
        AudClaim::Many(_) => None,
    })
}

/// Verifies Authentik-signed ID tokens and distills a [`Principal`]. The
/// validator keeps its own JWKS provider because the dashboard audience
/// (client_id) differs from the API resource audience.
pub struct IdTokenValidator {
    jwks: Arc<JwksProvider>,
    issuer: String,
    audience: String,
    algorithms: Vec<Algorithm>,
}

impl IdTokenValidator {
    pub fn new(
        jwks: Arc<JwksProvider>,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Self {
        Self {
            jwks,
            issuer: issuer.into(),
            audience: audience.into(),
            algorithms: vec![Algorithm::RS256, Algorithm::RS512, Algorithm::ES256],
        }
    }

    pub async fn validate(&self, token: &str) -> Result<Principal, IdTokenError> {
        self.validate_full(token).await.map(|(p, _, _)| p)
    }

    /// Like [`Self::validate`], but also returns the ID token's `azp`
    /// (authorized party = client). Used by the EMA token-exchange resolver
    /// to bind the authenticated client into a minted ID-JAG. `None` when the
    /// IdP omits `azp`.
    pub async fn validate_with_client_id(
        &self,
        token: &str,
    ) -> Result<(Principal, Option<String>), IdTokenError> {
        self.validate_full(token)
            .await
            .map(|(p, client, _)| (p, client))
    }

    /// Validate a dashboard ID token and return the signed assurance claims
    /// needed to build a factor-bearing encrypted session. The normal bearer
    /// identity remains the same [`Principal`]; only dashboard approval code
    /// consumes the additional context.
    pub async fn validate_with_assurance(
        &self,
        token: &str,
    ) -> Result<(Principal, IdTokenAssurance), IdTokenError> {
        self.validate_full(token)
            .await
            .map(|(p, _, assurance)| (p, assurance))
    }

    async fn validate_full(
        &self,
        token: &str,
    ) -> Result<(Principal, Option<String>, IdTokenAssurance), IdTokenError> {
        let header = decode_header(token)?;
        if !self.algorithms.contains(&header.alg) {
            return Err(IdTokenError::UnsupportedAlg(header.alg));
        }
        let kid = header.kid.ok_or(IdTokenError::MissingKid)?;
        let key = self.jwks.decoding_key(&kid).await?;

        let mut v = Validation::new(header.alg);
        v.set_issuer(&[self.issuer.as_str()]);
        v.set_audience(&[self.audience.as_str()]);
        v.leeway = 30;

        let data = decode::<IdClaims>(token, &key, &v)?;
        let c = data.claims;
        let client_id = id_token_client(c.azp.as_deref(), &c.aud);
        let assurance = IdTokenAssurance {
            auth_time: c.auth_time,
            amr: c.amr,
            acr: c.acr,
        };
        let scopes = c
            .scope
            .map(|s| s.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default();
        // Log the tenant the
        // dashboard principal is being stamped with when
        // it's anything other than `default`, so an operator
        // commissioning a multi-tenant dashboard can verify the
        // JWT claim is plumbed correctly without enabling debug
        // logging on every request.
        let tenant = crate::validator::parse_tenant_claim(c.tenant.as_ref());
        if tenant != waygate_core::TenantId::default() {
            tracing::debug!(
                sub = %c.sub,
                tenant = %tenant.as_str(),
                "id-token validator: principal tenant resolved from JWT `tenant` claim",
            );
        }
        let principal = Principal {
            sub: c.sub,
            email: c.email,
            groups: c.groups,
            issuer: c.iss,
            scopes,
            // Plumb the JWT `tenant`
            // claim through the same way the access-token
            // validator does. Without this the dashboard always
            // runs as default-tenant, so a suspended non-default
            // tenant's user could still reach /admin even with
            // the same `PgTenantEnricher` wired into the
            // dashboard session middleware (the enricher would
            // see `default`, look up `default` → Active, and let
            // the request through).
            tenant,
            auth_method: crate::AuthMethod::Oauth,
            // ID tokens aren't usable as subject_tokens for RFC 8693 exchange
            // (Authentik's exchange endpoint expects an access token). Leave
            // this `None` — the dashboard session path that uses id_token
            // validation doesn't hit the upstream call path.
            raw_token: None,
            // SCIM enrichment runs in the bearer
            // middleware path; the id-token validator is the
            // dashboard-session path which doesn't currently enrich.
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        };
        Ok((principal, client_id, assurance))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin that the JWT
    // `tenant` claim deserializes into IdClaims.tenant so the
    // validator's `parse_tenant_claim(c.tenant.as_ref())` sees
    // it. Without this serde drift (someone renaming the field
    // or stripping the `#[serde(default)]`) would silently
    // re-introduce the dashboard-always-default-tenant bug.
    #[test]
    fn id_claims_carries_tenant_string() {
        let json = r#"{
            "sub": "alice",
            "iss": "https://idp.example",
            "aud": "dashboard-client",
            "tenant": "acme"
        }"#;
        let c: IdClaims = serde_json::from_str(json).unwrap();
        assert_eq!(c.tenant.as_ref().and_then(|v| v.as_str()), Some("acme"),);
    }

    #[test]
    fn id_claims_tenant_missing_is_none() {
        let json = r#"{
            "sub": "alice",
            "iss": "https://idp.example",
            "aud": "dashboard-client"
        }"#;
        let c: IdClaims = serde_json::from_str(json).unwrap();
        assert!(c.tenant.is_none());
    }

    #[test]
    fn id_claims_carries_authentication_assurance() {
        let json = r#"{
            "sub": "alice",
            "iss": "https://idp.example",
            "aud": "dashboard-client",
            "auth_time": 1710000000,
            "amr": ["pwd", "webauthn", "mfa"],
            "acr": "urn:example:mfa"
        }"#;
        let c: IdClaims = serde_json::from_str(json).unwrap();
        assert_eq!(c.auth_time, Some(1_710_000_000));
        assert_eq!(c.amr, ["pwd", "webauthn", "mfa"]);
        assert_eq!(c.acr.as_deref(), Some("urn:example:mfa"));
    }

    #[test]
    fn id_claims_defaults_missing_assurance() {
        let json = r#"{
            "sub": "alice",
            "iss": "https://idp.example",
            "aud": "dashboard-client"
        }"#;
        let c: IdClaims = serde_json::from_str(json).unwrap();
        assert_eq!(c.auth_time, None);
        assert!(c.amr.is_empty());
        assert_eq!(c.acr, None);
    }

    // EMA subject-token client binding. `azp` wins when present;
    // otherwise a single `aud` is the client; a multi-`aud` token with no `azp`
    // is ambiguous and must not bind (fail-closed).
    #[test]
    fn id_token_client_prefers_azp() {
        let aud = AudClaim::One("the-aud-client".into());
        assert_eq!(
            id_token_client(Some("the-azp-client"), &aud),
            Some("the-azp-client".to_owned()),
        );
    }

    #[test]
    fn id_token_client_falls_back_to_single_aud() {
        let aud = AudClaim::One("the-aud-client".into());
        assert_eq!(
            id_token_client(None, &aud),
            Some("the-aud-client".to_owned()),
            "a standard single-audience ID token binds to its aud when azp is absent",
        );
    }

    #[test]
    fn id_token_client_multi_aud_without_azp_is_none() {
        let aud = AudClaim::Many(vec!["a".into(), "b".into()]);
        assert_eq!(
            id_token_client(None, &aud),
            None,
            "multi-audience with no azp is ambiguous — must not bind a client",
        );
    }
}
