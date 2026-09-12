//! Bearer-token validator — signature + `iss` + `aud` + `exp`, plus distilled
//! [`Principal`](crate::Principal) extraction from the decoded claims.

use std::sync::Arc;

use async_trait::async_trait;
use jsonwebtoken::{decode, decode_header, Algorithm, Validation};
use serde::Deserialize;
use thiserror::Error;

use std::collections::HashMap;

use crate::header_validator::HeaderValidator;
use crate::jwks::{JwksError, JwksProvider};
use crate::{ApiKeyProfileRestrictions, AuthMethod, Principal};

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("missing Authorization header")]
    Missing,
    #[error("invalid Authorization header format (expected `Bearer <token>`)")]
    Malformed,
    #[error("token header missing `kid`")]
    MissingKid,
    #[error("jwt: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("jwks: {0}")]
    Jwks(#[from] JwksError),
    #[error("missing required scope `{0}`")]
    MissingScope(String),
    /// The token passed the (additive) EMA audience-membership gate
    /// because its `aud` array contained a registered per-upstream resource
    /// id, but the array names *more than one* resource id — there is no
    /// single upstream to confine the token to. Fail closed rather than
    /// fall back to an unrestricted (estate-wide) principal. A client error
    /// (401), not infra.
    #[error("ambiguous resource audience: token `aud` names {0} registered resource ids; cannot confine to a single upstream")]
    AmbiguousResourceAudience(usize),
    /// Infra-class failure from a non-JWKS validator (e.g. database
    /// unreachable for the API-key validator). Surfaced as 503 by the
    /// middleware so a single validator's storage outage doesn't get
    /// silently converted into a "bad token" 401.
    #[error("validator infra: {0}")]
    Infra(String),
}

impl ValidationError {
    /// Distinguishes "this token isn't valid for this validator" (client error
    /// — fall through to the next validator in the chain or 401) from "the
    /// validator couldn't reach its key infrastructure" (infra error — 503).
    ///
    /// `Jwks(UnknownKid)` is a client error: in a multi-validator chain it
    /// just means the token was issued by the IdP this validator is *not*
    /// configured for. Treating it as infra would prevent the next validator
    /// from being tried even when it would happily accept the token.
    pub fn is_client_error(&self) -> bool {
        match self {
            ValidationError::Missing
            | ValidationError::Malformed
            | ValidationError::MissingKid
            | ValidationError::Jwt(_)
            | ValidationError::MissingScope(_)
            | ValidationError::AmbiguousResourceAudience(_) => true,
            ValidationError::Jwks(JwksError::UnknownKid(_)) => true,
            ValidationError::Jwks(_) => false,
            ValidationError::Infra(_) => false,
        }
    }
}

/// Claims we actually consume. Anything else in the JWT is ignored.
#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default, deserialize_with = "deser_scope")]
    scope: Vec<String>,
    #[serde(default)]
    groups: Vec<String>,
    /// The OAuth client the access token was issued to. Gateway-minted
    /// access tokens carry this (`AccessTokenClaims.client_id`); upstream
    /// IdP tokens may not. Surfaced via [`BearerValidator::validate_with_client_id`]
    /// so the EMA token-exchange can bind the *authenticated* client into a
    /// minted ID-JAG rather than trusting a caller-supplied form value.
    #[serde(default)]
    client_id: Option<String>,
    /// The token's audience, used for EMA resource binding. `jsonwebtoken` validates *membership*
    /// against the accepted set via `set_audience`; we additionally READ it
    /// here to learn WHICH audience(s) matched — a per-upstream RFC 9728 resource
    /// id (`{public_url}/servers/<name>`) means the token is resource-scoped and
    /// the validator records the server binding. Typed as a raw JSON value so a
    /// multi-valued `aud` array doesn't fail decode; [`resolve_resource_binding`]
    /// then inspects every entry (string *or* array) fail-closed — see that
    /// function for the 0 / 1 / ≥2 resource-id resolution.
    #[serde(default)]
    aud: Option<serde_json::Value>,
    /// Tenant ID from the literal `tenant` claim. Missing or invalid values
    /// resolve to the default tenant.
    ///
    /// Typed as a raw JSON value (not `Option<String>`) so an IdP
    /// that emits a non-string `tenant` claim — integer, array,
    /// object — doesn't fail JWT decode entirely. The
    /// `parse_tenant_claim` helper falls back to the default
    /// tenant for any non-string value.
    #[serde(default)]
    tenant: Option<serde_json::Value>,
}

pub struct BearerValidator {
    jwks: Arc<JwksProvider>,
    issuers: Vec<String>,
    audience: String,
    /// Per-upstream RFC 9728 resource ids → server name. A token
    /// whose `aud` is one of these keys is accepted (additive to `audience`)
    /// and recorded as a single-server call restriction.
    resource_audiences: HashMap<String, String>,
    algorithms: Vec<Algorithm>,
}

impl BearerValidator {
    pub fn new(
        jwks: Arc<JwksProvider>,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Self {
        Self {
            jwks,
            issuers: vec![issuer.into()],
            audience: audience.into(),
            resource_audiences: HashMap::new(),
            // RS256/RS512/ES256 cover typical OIDC IdPs (Authentik = RS256).
            // EdDSA covers the gateway's own Ed25519 signing key in AS mode —
            // so a single validator trusts both upstream and gateway-minted
            // tokens without callsite-specific widening.
            algorithms: vec![
                Algorithm::RS256,
                Algorithm::RS512,
                Algorithm::ES256,
                Algorithm::EdDSA,
            ],
        }
    }

    /// Override the accepted algorithms (default: RS256, RS512, ES256, EdDSA).
    pub fn with_algorithms(mut self, algs: Vec<Algorithm>) -> Self {
        self.algorithms = algs;
        self
    }

    /// The algorithms this validator accepts. Exposed so the crypto-backend
    /// contract test (`tests/suite/crypto_backend_algorithms.rs`) can assert that the
    /// configured `jsonwebtoken` backend actually signs+verifies every one of
    /// them — the regression guard for the 2026-06-10 boot deadlock where a
    /// backend swap (#289) broke the first JWT crypto op at startup.
    pub fn algorithms(&self) -> &[Algorithm] {
        &self.algorithms
    }

    /// Accept additional `iss` values beyond the one passed to `new()`.
    /// Authentik's `issuer_mode=per_provider` mints a distinct issuer URL per
    /// OAuth2 provider (e.g. `/application/o/<slug>/`), so M2M service-account
    /// providers each have their own issuer string distinct from the gateway's
    /// own provider. The JWKS endpoint is shared across the realm, so the same
    /// `JwksProvider` validates all of them — only the `iss` allowlist widens.
    pub fn with_additional_issuers(mut self, additional: Vec<String>) -> Self {
        self.issuers.extend(additional);
        self
    }

    /// Register per-upstream RFC 9728 resource ids for EMA audience binding
    /// (`{public_url}/servers/<name>` → server name). Their keys join the
    /// accepted-audience set (additive to the estate `audience` from `new()`),
    /// and a token whose `aud` is one of them is recorded as a single-server
    /// call restriction — reusing `Principal.api_key_profile_restrictions`, the
    /// general per-principal server/tool allow-list the invocation gate and
    /// tools/list filter already enforce, so a resource-scoped (EMA-redeemed)
    /// token is confined to its one upstream. (A dedicated `Principal` field
    /// would mean editing ~180 struct-literal sites; this reuses the existing,
    /// already-enforced mechanism instead.)
    pub fn with_resource_audiences(mut self, map: HashMap<String, String>) -> Self {
        self.resource_audiences = map;
        self
    }

    /// Parse `Authorization: Bearer <token>` and validate the token.
    pub async fn validate_header(&self, header: &str) -> Result<Principal, ValidationError> {
        let token = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))
            .ok_or(ValidationError::Malformed)?;
        self.validate(token).await
    }

    pub async fn validate(&self, token: &str) -> Result<Principal, ValidationError> {
        self.validate_with_client_id(token).await.map(|(p, _)| p)
    }

    /// Like [`Self::validate`], but also returns the token's `client_id`
    /// claim (`None` when absent). The EMA token-exchange resolver uses this
    /// to bind the *authenticated* client into the minted ID-JAG, instead of
    /// trusting a caller-supplied `client_id` form field — a caller must not
    /// be able to obtain an assertion bound to a client it didn't authenticate
    /// as.
    pub async fn validate_with_client_id(
        &self,
        token: &str,
    ) -> Result<(Principal, Option<String>), ValidationError> {
        let header = decode_header(token)?;
        if !self.algorithms.contains(&header.alg) {
            return Err(ValidationError::Jwt(jsonwebtoken::errors::Error::from(
                jsonwebtoken::errors::ErrorKind::InvalidAlgorithm,
            )));
        }
        let kid = header.kid.ok_or(ValidationError::MissingKid)?;
        let key = self.jwks.decoding_key(&kid).await?;

        // jsonwebtoken requires every alg in `Validation.algorithms` to share
        // the key's family; mixing RSA + EC entries triggers InvalidAlgorithm.
        // Narrow to the header alg (already vetted against our allowlist).
        let mut v = Validation::new(header.alg);
        let issuers: Vec<&str> = self.issuers.iter().map(String::as_str).collect();
        v.set_issuer(&issuers);
        // EMA audience binding: accept the estate audience PLUS any registered
        // per-upstream resource id (additive). jsonwebtoken passes the token if its `aud`
        // matches ANY of these; we then read `aud` to resolve the binding.
        let mut auds: Vec<&str> = Vec::with_capacity(1 + self.resource_audiences.len());
        auds.push(self.audience.as_str());
        auds.extend(self.resource_audiences.keys().map(String::as_str));
        v.set_audience(&auds);
        v.leeway = 30;

        let data = decode::<Claims>(token, &key, &v)?;
        let c = data.claims;
        let client_id = c.client_id;
        // EMA: if the token's audience is a per-upstream resource id, record
        // the single-server binding so the invocation gate + tools/list filter
        // confine this token to that upstream. Fails closed (not estate-wide) when
        // a multi-valued `aud` names more than one registered resource id.
        let resource_restriction =
            resolve_resource_binding(c.aud.as_ref(), &self.resource_audiences)?;
        let principal = Principal {
            sub: c.sub,
            email: c.email,
            groups: c.groups,
            issuer: c.iss,
            scopes: c.scope,
            tenant: parse_tenant_claim(c.tenant.as_ref()),
            auth_method: AuthMethod::Oauth,
            raw_token: Some(token.to_owned()),
            // SCIM attrs are filled by the optional
            // PrincipalEnricher in BearerLayer after this validator
            // returns. None ⇒ no enricher wired OR no scim_users row
            // for this `sub` in this tenant.
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: resource_restriction,
        };
        Ok((principal, client_id))
    }

    pub fn require_scope(principal: &Principal, scope: &str) -> Result<(), ValidationError> {
        if principal.has_scope(scope) {
            Ok(())
        } else {
            Err(ValidationError::MissingScope(scope.to_owned()))
        }
    }
}

#[async_trait]
impl HeaderValidator for BearerValidator {
    async fn validate_header(&self, header: &str) -> Result<Principal, ValidationError> {
        // UFCS to avoid recursing into the trait method.
        BearerValidator::validate_header(self, header).await
    }
}

/// Map a raw `tenant` claim value to a `TenantId`.
/// An absent, non-string, or invalid claim falls back to the
/// default tenant — it would be a security bug to let a JWT with
/// a malformed tenant claim land in an enforcing tenant slot, so
/// we route it to the same `default` bucket single-tenant
/// deployments live in. Invalid claims are logged at WARN so an
/// operator notices the misconfigured IdP instead of discovering
/// it via principals silently landing in the default tenant.
///
/// Accepts any JSON value (not just `String`) so an IdP that
/// emits a non-string `tenant` claim doesn't fail JWT decode
/// entirely — only `Value::String` is considered; other shapes
/// fall back to default with a WARN.
pub(crate) fn parse_tenant_claim(raw: Option<&serde_json::Value>) -> waygate_core::TenantId {
    let Some(raw) = raw else {
        return waygate_core::TenantId::default();
    };
    let Some(s) = raw.as_str() else {
        tracing::warn!(
            tenant_claim = %raw,
            "JWT carried a non-string `tenant` claim; falling back to default tenant",
        );
        return waygate_core::TenantId::default();
    };
    match waygate_core::TenantId::parse(s) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(
                tenant_claim = %s,
                error = %e,
                "JWT carried a `tenant` claim that does not match TenantId format; \
                 falling back to default tenant",
            );
            waygate_core::TenantId::default()
        }
    }
}

/// Resolve a token's `aud` to a single-server call restriction when
/// it carries a registered per-upstream RFC 9728 resource id. Returned as an
/// [`ApiKeyProfileRestrictions`] — the general per-principal server/tool
/// allow-list the invocation gate and tools/list filter already enforce — so a
/// resource-scoped token is confined to its one upstream without a dedicated
/// `Principal` field (which would touch ~180 struct-literal sites).
///
/// The audience-membership gate (`Validation::set_audience`) accepts a token if
/// `aud` matches *any* member of `{estate audience} ∪ {resource ids}`. For a
/// multi-valued `aud` array that is too coarse on its own: an array containing a
/// registered resource id passes the gate, so this function must derive the
/// binding *fail-closed* from every recognized resource id in the claim, not
/// just a single-string `aud`. A single-string-only
/// implementation fails open: an `aud` array `["…/servers/example-observability", "…/attacker"]` passes
/// the gate but resolves to `None`, silently promoting a resource-scoped token
/// to an unrestricted estate principal.
///
/// Outcomes, by the count of *registered* resource ids present in `aud`
/// (deduplicated; a non-string/array `aud` shape contributes none):
/// - **0** → `Ok(None)`: no resource id named. The gate already proved `aud`
///   matched the estate audience, so this is a legitimately estate-wide
///   (unrestricted) token.
/// - **1** → `Ok(Some(binding))`: confine to that one upstream. This holds even
///   if the estate audience is *also* present — binding to the named resource is
///   strictly more restrictive than estate-wide and satisfies "exactly one
///   server", so it can never escalate a token's reach.
/// - **≥2** → `Err(AmbiguousResourceAudience)`: the token names multiple
///   upstreams; there is no single server to confine it to. Reject rather than
///   fall back to unrestricted.
fn resolve_resource_binding(
    aud: Option<&serde_json::Value>,
    resource_audiences: &HashMap<String, String>,
) -> Result<Option<ApiKeyProfileRestrictions>, ValidationError> {
    // Deduplicate so an `aud` that repeats one resource id (`[g, g]`) is treated
    // as a single binding, not a false "ambiguous".
    let mut matched: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    match aud {
        // String `aud`: at most one resource id.
        Some(serde_json::Value::String(s)) if resource_audiences.contains_key(s) => {
            matched.insert(s.as_str());
        }
        // Array `aud`: collect every string element that is a registered id.
        Some(serde_json::Value::Array(items)) => {
            for s in items.iter().filter_map(serde_json::Value::as_str) {
                if resource_audiences.contains_key(s) {
                    matched.insert(s);
                }
            }
        }
        // Absent or any other JSON shape: no resource id. (A scalar/object `aud`
        // cannot have matched a string audience in the gate, so this branch is
        // only reachable for an estate-audience token — unrestricted.)
        _ => {}
    }

    match matched.len() {
        0 => Ok(None),
        1 => {
            let server = resource_audiences
                .get(*matched.iter().next().expect("len==1"))
                .expect("matched ids are keys of resource_audiences");
            Ok(Some(ApiKeyProfileRestrictions {
                profile_id: "id-jag:resource".to_owned(),
                profile_name: format!("ID-JAG resource binding ({server})"),
                allowed_servers: Some(vec![server.clone()]),
                allowed_tools: None,
            }))
        }
        n => Err(ValidationError::AmbiguousResourceAudience(n)),
    }
}

/// Accepts either a space-separated string (the OAuth 2.0 default) or a
/// JSON array (some IdPs emit it that way).
fn deser_scope<'de, D>(de: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let v = serde_json::Value::deserialize(de)?;
    match v {
        serde_json::Value::String(s) => Ok(s.split_whitespace().map(str::to_owned).collect()),
        serde_json::Value::Array(items) => items
            .into_iter()
            .map(|i| match i {
                serde_json::Value::String(s) => Ok(s),
                other => Err(D::Error::custom(format!(
                    "scope entry not a string: {other}"
                ))),
            })
            .collect(),
        serde_json::Value::Null => Ok(Vec::new()),
        other => Err(D::Error::custom(format!(
            "expected string or array for `scope`, got {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_tenant_claim, resolve_resource_binding, ValidationError};
    use serde_json::json;
    use std::collections::HashMap;
    use waygate_core::TenantId;

    const EXAMPLE_OBSERVABILITY: &str = "https://mcp.test/servers/example-observability";
    const PROMETHEUS: &str = "https://mcp.test/servers/prometheus";
    const ESTATE: &str = "https://mcp.test/mcp";

    fn resource_map() -> HashMap<String, String> {
        HashMap::from([
            (
                EXAMPLE_OBSERVABILITY.to_owned(),
                "example-observability".to_owned(),
            ),
            (PROMETHEUS.to_owned(), "prometheus".to_owned()),
        ])
    }

    /// A single-server binding result must confine to exactly that server.
    #[track_caller]
    fn assert_binds_to(
        r: Result<Option<super::ApiKeyProfileRestrictions>, ValidationError>,
        server: &str,
    ) {
        let binding = r
            .expect("must not be rejected")
            .expect("a known resource-id aud must bind");
        assert_eq!(
            binding.allowed_servers.as_deref(),
            Some(&[server.to_owned()][..])
        );
        assert_eq!(binding.allowed_tools, None);
    }

    #[test]
    fn resource_binding_for_known_resource_aud() {
        // Single-string resource id → bind.
        assert_binds_to(
            resolve_resource_binding(Some(&json!(EXAMPLE_OBSERVABILITY)), &resource_map()),
            "example-observability",
        );
    }

    #[test]
    fn no_binding_for_estate_or_absent_aud() {
        let map = resource_map();
        // Estate audience (not a resource id) → unrestricted.
        assert!(resolve_resource_binding(Some(&json!(ESTATE)), &map)
            .expect("estate aud is valid")
            .is_none());
        // Absent aud → unrestricted.
        assert!(resolve_resource_binding(None, &map)
            .expect("absent aud is valid")
            .is_none());
        // A non-string/array `aud` shape contributes no resource id → unrestricted
        // (in production the gate would have rejected such a token before this).
        assert!(resolve_resource_binding(Some(&json!(42)), &map)
            .expect("scalar aud yields no binding")
            .is_none());
    }

    /// The fail-open this guards against: a multi-valued `aud` array
    /// containing a *single* registered resource id must BIND to that one
    /// upstream — not silently resolve to an unrestricted estate principal.
    #[test]
    fn single_resource_in_array_binds_fail_closed() {
        let map = resource_map();
        // resource id + an unrelated/attacker audience → still confined to example-observability.
        assert_binds_to(
            resolve_resource_binding(
                Some(&json!([
                    EXAMPLE_OBSERVABILITY,
                    "https://attacker.example/x"
                ])),
                &map,
            ),
            "example-observability",
        );
        // resource id alongside the estate audience → the resource binding wins
        // (strictly more restrictive than estate-wide; "exactly one server").
        assert_binds_to(
            resolve_resource_binding(Some(&json!([ESTATE, EXAMPLE_OBSERVABILITY])), &map),
            "example-observability",
        );
        // A repeated single resource id is one binding, not "ambiguous".
        assert_binds_to(
            resolve_resource_binding(
                Some(&json!([EXAMPLE_OBSERVABILITY, EXAMPLE_OBSERVABILITY])),
                &map,
            ),
            "example-observability",
        );
    }

    /// An `aud` array naming two *different* registered resource ids has no single
    /// upstream to confine to → reject (fail closed), never fall back to estate.
    #[test]
    fn multiple_resource_ids_in_array_are_rejected() {
        let map = resource_map();
        let err = resolve_resource_binding(Some(&json!([EXAMPLE_OBSERVABILITY, PROMETHEUS])), &map)
            .expect_err("two distinct resource ids must be rejected");
        match err {
            ValidationError::AmbiguousResourceAudience(2) => {}
            other => panic!("expected AmbiguousResourceAudience(2), got {other:?}"),
        }
        // It is a client error (401), not infra (503).
        assert!(ValidationError::AmbiguousResourceAudience(2).is_client_error());
    }

    /// An array of only unregistered values names no resource id → unrestricted
    /// here (the audience gate is what rejects it in production).
    #[test]
    fn array_with_no_registered_resource_id_yields_no_binding() {
        assert!(resolve_resource_binding(
            Some(&json!([
                "https://other.example/a",
                "https://other.example/b"
            ])),
            &resource_map(),
        )
        .expect("no registered id present")
        .is_none());
    }

    #[test]
    fn missing_tenant_claim_falls_back_to_default() {
        assert_eq!(parse_tenant_claim(None), TenantId::default());
    }

    #[test]
    fn valid_tenant_claim_is_parsed_through() {
        let v = json!("acme-prod");
        let t = parse_tenant_claim(Some(&v));
        assert_eq!(t.as_str(), "acme-prod");
        assert!(!t.is_default());
    }

    #[test]
    fn invalid_tenant_claim_falls_back_to_default() {
        // Uppercase isn't allowed in TenantId; the validator
        // must NOT crash and must NOT route the principal into a
        // sub-tenant that an attacker controls — fall back to
        // the default tenant and log loud (the WARN is in the
        // production path; tracing capture isn't wired into this
        // crate's unit tests).
        let v = json!("Acme");
        let t = parse_tenant_claim(Some(&v));
        assert_eq!(t, TenantId::default());
    }

    #[test]
    fn empty_tenant_claim_falls_back_to_default() {
        let v = json!("");
        let t = parse_tenant_claim(Some(&v));
        assert_eq!(t, TenantId::default());
    }

    /// A non-string `tenant` claim
    /// (integer, array, object) must NOT fail JWT decode
    /// entirely; it falls back to the default tenant alongside
    /// the absent / malformed-string paths.
    #[test]
    fn non_string_tenant_claim_falls_back_to_default() {
        for raw in [json!(42), json!(["a", "b"]), json!({"k": "v"}), json!(null)] {
            assert_eq!(
                parse_tenant_claim(Some(&raw)),
                TenantId::default(),
                "non-string `tenant` claim {raw:?} must fall back to default tenant",
            );
        }
    }
}
