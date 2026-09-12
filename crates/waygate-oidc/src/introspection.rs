//! RFC 7662 OAuth 2.0 Token Introspection.
//!
//! For deployments where the upstream IdP issues OPAQUE access
//! tokens (Authentik with `provider_type=oauth2` and
//! `signing_key=None`, or any IdP configured to mint
//! non-JWT bearers), the gateway can't validate the token
//! locally. RFC 7662 lets the gateway POST the bearer to a
//! protected introspection endpoint and trust the IdP's
//! `active=true/false` reply.
//!
//! ## Where this fits in the bearer chain
//!
//! `waygate-oidc::middleware::BearerLayer` iterates a
//! `Vec<Arc<dyn HeaderValidator>>`. The introspection
//! validator is wired AFTER the JWT validator and BEFORE the
//! API-key validator:
//!
//!   1. JWT validator — fastest path (signature verify only,
//!      no IdP hop). Accepts every well-formed signed JWT
//!      from the configured issuer.
//!   2. **Introspection validator (this file)** — for
//!      tokens that don't parse as JWTs (3 `.`-separated
//!      base64url segments) and don't look like static
//!      gateway-minted API keys (`mcpgw_…`). One HTTP POST
//!      per cold-cache token.
//!   3. API-key validator — argon2 + DB lookup.
//!
//! Each step returns `Err(ValidationError::Malformed)` (a
//! client error, per `is_client_error()`) when the token
//! doesn't match its expected shape, which causes
//! `BearerLayer` to fall through to the next step. The
//! middleware emits a single 401 only after every step
//! returns a client error.
//!
//! ## Caching shape
//!
//! `moka::future::Cache` with two slots:
//!
//! - **Positive cache** keyed on the opaque token string,
//!   value the resolved `Principal`. TTL is the smaller of
//!   `min(exp_unix - now, config.max_positive_ttl)` so a
//!   revoked-at-the-IdP token can re-validate as inactive
//!   inside one TTL window (default 300s). A token with no
//!   `exp` falls back to `max_positive_ttl` exactly —
//!   neither shorter (would over-load the IdP) nor longer
//!   (would defeat the IdP's revocation TTL).
//!
//! - **Negative cache** keyed on the opaque token string,
//!   value `()`. TTL is `config.negative_ttl` (default 30s
//!   — short on purpose so a transient IdP wobble doesn't
//!   strand a token longer than the operator would expect
//!   from cause-effect). RFC 7662 says
//!   `active=false` is atomic: once the IdP says inactive,
//!   the same token will keep saying inactive, so even a
//!   long negative TTL would be correct; the 30s default is
//!   just a defense against IdP-side flapping.
//!
//! ## What we do NOT do
//!
//! - **Token type sniffing beyond shape.** A token that
//!   PARSES as a JWT shape (3 segments) is left for the
//!   JWT validator even if the IdP would also introspect
//!   it; the JWT validator is faster and the signature
//!   verify is the same trust anchor.
//! - **DPoP / mTLS sender-constrained tokens.** RFC 7662
//!   §2.2 says introspection responses MAY carry `cnf`
//!   confirmation claims; the gateway doesn't enforce
//!   binding today. When DPoP lands as a follow-up, the
//!   validator gains a `cnf` check before stamping the
//!   principal.
//! - **Mass revocation propagation.** Operators expecting
//!   instant revocation should configure short positive
//!   TTL (`GATEWAY_INTROSPECTION_CACHE_TTL_SECONDS=10`).
//!   The validator itself doesn't subscribe to any
//!   IdP-side revocation event channel.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use moka::future::Cache;
use moka::Expiry;
use serde::Deserialize;
use serde_json::Value;
use time::OffsetDateTime;

use crate::header_validator::HeaderValidator;
use crate::validator::ValidationError;
use crate::{AuthMethod, Principal};
use waygate_core::http_client::{self, Profile};

/// Runtime configuration for [`OpaqueTokenValidator`].
///
/// `Debug` is implemented
/// manually below to elide `client_secret`. Adding the
/// derive would expose the secret in any `tracing::debug!`
/// or `panic!` formatter call.
#[derive(Clone)]
pub struct IntrospectionConfig {
    /// RFC 7662 §2.1 introspection endpoint URL.
    pub introspection_url: String,
    /// `client_id` the gateway authenticates to the
    /// introspection endpoint with. The IdP must have an
    /// OAuth client registered specifically for this purpose
    /// (RFC 7662 §2.1 SHOULD require client auth).
    pub client_id: String,
    /// `client_secret` for that client. Stored in process
    /// memory only — never logged via `Debug` (the field is
    /// elided in the manual `Debug` impl below).
    pub client_secret: String,
    /// `iss` value the gateway stamps onto the returned
    /// [`Principal`] (mirrors how the JWT validator uses the
    /// configured Authentik issuer). RFC 7662 doesn't
    /// require the introspection response itself to echo
    /// `iss`; treating the configured value as canonical
    /// keeps audit logs comparable across the two
    /// validators.
    pub issuer: String,
    /// Expected audience for the introspected token.
    /// Security invariant: when this is
    /// non-empty the introspection response MUST carry an
    /// `aud` claim and `expected_audience` MUST appear in
    /// it (string or array form). A missing `aud` is
    /// rejected — mirrors the JWT validator's
    /// `set_audience` (which requires presence, not just
    /// non-mismatch) so a misconfigured IdP sharing an
    /// introspection endpoint across multiple RPs cannot
    /// hand the gateway a cross-RP token. When empty
    /// (test fixtures / single-RP IdPs that scope at the
    /// endpoint) the `aud` check is skipped entirely. Set
    /// to the same value as the JWT validator's audience
    /// (`GATEWAY_AUDIENCE`).
    pub expected_audience: String,
    /// Claim used to populate `Principal.tenant`. The gateway supplies
    /// `tenant` to match JWT validation and preserve consistent attribution.
    pub tenant_claim: String,
    /// Ceiling on the positive cache TTL. The effective
    /// TTL is `min(exp - now, max_positive_ttl)` so a
    /// revoked-at-the-IdP token re-validates as inactive
    /// within this window.
    pub max_positive_ttl: Duration,
    /// Negative cache TTL — how long an `active=false`
    /// introspection response stays cached before the
    /// validator will retry the IdP for the same token.
    /// Default 30s.
    pub negative_ttl: Duration,
    /// Cap on total cached tokens (positive + negative).
    /// Default 8192 — enough headroom for typical
    /// deployments without unbounded growth.
    pub cache_capacity: u64,
}

impl std::fmt::Debug for IntrospectionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Elide `client_secret` so a stray
        // `tracing::debug!(?cfg)` doesn't leak the
        // introspection-client credentials. Mirrors the
        // pattern on `OpaqueTokenValidator::Debug`.
        f.debug_struct("IntrospectionConfig")
            .field("introspection_url", &self.introspection_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("issuer", &self.issuer)
            .field("expected_audience", &self.expected_audience)
            .field("tenant_claim", &self.tenant_claim)
            .field("max_positive_ttl", &self.max_positive_ttl)
            .field("negative_ttl", &self.negative_ttl)
            .field("cache_capacity", &self.cache_capacity)
            .finish()
    }
}

impl Default for IntrospectionConfig {
    fn default() -> Self {
        Self {
            introspection_url: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            issuer: String::new(),
            expected_audience: String::new(),
            tenant_claim: "tenant".into(),
            max_positive_ttl: Duration::from_secs(300),
            negative_ttl: Duration::from_secs(30),
            cache_capacity: 8192,
        }
    }
}

/// RFC 7662 introspection validator. Construct via
/// [`OpaqueTokenValidator::new`]; chain into the bearer
/// middleware via `Arc<dyn HeaderValidator>`.
/// Cache entry carrying the resolved `Principal` plus the
/// per-entry TTL the [`PerEntryExpiry`] hook returns. The
/// TTL is computed at insert time as `min(exp - now,
/// config.max_positive_ttl)` so a short-lived token never
/// outlives its IdP `exp`.
#[derive(Clone, Debug)]
struct CachedPrincipal {
    principal: Principal,
    ttl: Duration,
}

/// moka `Expiry` impl that returns `value.ttl` for each
/// insertion. Together with a `time_to_live` ceiling on the
/// cache builder, this gives true per-entry TTL: the cache
/// honours the shorter of the per-entry TTL and the builder
/// default.
struct PerEntryExpiry;

impl Expiry<String, CachedPrincipal> for PerEntryExpiry {
    fn expire_after_create(
        &self,
        _key: &String,
        value: &CachedPrincipal,
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(value.ttl)
    }
}

pub struct OpaqueTokenValidator {
    config: IntrospectionConfig,
    http: reqwest::Client,
    positive: Cache<String, CachedPrincipal>,
    negative: Cache<String, ()>,
}

impl std::fmt::Debug for OpaqueTokenValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Elide client_secret + http (Cache doesn't impl Debug usefully).
        f.debug_struct("OpaqueTokenValidator")
            .field("introspection_url", &self.config.introspection_url)
            .field("client_id", &self.config.client_id)
            .field("issuer", &self.config.issuer)
            .field("expected_audience", &self.config.expected_audience)
            .field("max_positive_ttl", &self.config.max_positive_ttl)
            .field("negative_ttl", &self.config.negative_ttl)
            .finish_non_exhaustive()
    }
}

impl OpaqueTokenValidator {
    /// Build with a custom HTTP client (used by tests for
    /// loopback wiring).
    pub fn with_client(config: IntrospectionConfig, http: reqwest::Client) -> Arc<Self> {
        // Per-entry TTL via the
        // `Expiry` trait so a token's cached lifetime is
        // `min(exp - now, max_positive_ttl)` — never longer
        // than the IdP's `exp`. The `time_to_live` ceiling
        // remains as a defense against an IdP that emits an
        // unreasonably long `exp` (or no `exp` at all, in
        // which case the entry's TTL would default to the
        // ceiling per `compute_positive_ttl`).
        let positive: Cache<String, CachedPrincipal> = Cache::builder()
            .max_capacity(config.cache_capacity)
            .time_to_live(config.max_positive_ttl)
            .expire_after(PerEntryExpiry)
            .build();
        let negative: Cache<String, ()> = Cache::builder()
            .max_capacity(config.cache_capacity)
            .time_to_live(config.negative_ttl)
            .build();
        Arc::new(Self {
            config,
            http,
            positive,
            negative,
        })
    }

    /// Default constructor — internal `reqwest::Client` with
    /// a 5s timeout. Production callers should prefer this;
    /// `with_client` exists for test injection.
    pub fn new(config: IntrospectionConfig) -> Result<Arc<Self>, String> {
        let http = http_client::builder(Profile::Interactive)
            .build()
            .map_err(|e| format!("introspection http client build: {e}"))?;
        Ok(Self::with_client(config, http))
    }
}

#[async_trait]
impl HeaderValidator for OpaqueTokenValidator {
    async fn validate_header(&self, header: &str) -> Result<Principal, ValidationError> {
        let token = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))
            .ok_or(ValidationError::Malformed)?;

        // Defer to JWT validator for anything JWT-shaped.
        // Three `.`-separated base64url segments is the
        // cheap structural test; matches what an upstream
        // BearerValidator would happily parse.
        if looks_like_jwt(token) {
            return Err(ValidationError::Malformed);
        }
        // Static API keys go to the API-key validator.
        if token.starts_with("mcpgw_") {
            return Err(ValidationError::Malformed);
        }

        if let Some(entry) = self.positive.get(token).await {
            return Ok(entry.principal);
        }
        if self.negative.get(token).await.is_some() {
            // Pretend not-mine so the chain falls through;
            // the middleware composes a single 401 at the
            // chain end. Caching the negative as "malformed
            // for us" mirrors what a successful introspect
            // saying active=false would have produced.
            return Err(ValidationError::Malformed);
        }

        // RFC 7662 §2.1: client auth via HTTP Basic with
        // client_id + client_secret. Body is form-encoded
        // `token=<value>&token_type_hint=access_token`.
        // reqwest is built `default-features=false` in this
        // workspace, so the convenience `.form()` builder
        // isn't compiled in. Hand-encode the
        // `application/x-www-form-urlencoded` body via
        // `url::form_urlencoded` (already a workspace dep)
        // so we don't widen the reqwest feature set just for
        // one request.
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("token", token)
            .append_pair("token_type_hint", "access_token")
            .finish();
        let resp = self
            .http
            .post(&self.config.introspection_url)
            .basic_auth(&self.config.client_id, Some(&self.config.client_secret))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .map_err(|e| ValidationError::Infra(format!("introspection POST: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            // RFC 7662 §2.3: any non-2xx is a protocol error.
            // 401/403 means our client creds are wrong (infra)
            // — don't poison the cache. 4xx other means the
            // request was malformed at the IdP's discretion
            // — also infra so an operator notices.
            return Err(ValidationError::Infra(format!(
                "introspection responded {status}"
            )));
        }
        let body: IntrospectionResponse = resp
            .json()
            .await
            .map_err(|e| ValidationError::Infra(format!("introspection response not JSON: {e}")))?;

        if !body.active {
            self.negative.insert(token.to_owned(), ()).await;
            return Err(ValidationError::Malformed);
        }

        // Enforce
        // token_type + audience binding on the active
        // response. See `enforce_active_invariants` for the
        // contract. On reject we negative-cache so a noisy
        // client can't hammer the IdP.
        if !enforce_active_invariants(&self.config, &body) {
            self.negative.insert(token.to_owned(), ()).await;
            return Err(ValidationError::Malformed);
        }

        let principal = build_principal(&self.config, &body)?;

        // Per-entry TTL = min(exp - now, ceiling). The
        // `PerEntryExpiry` hook on the cache builder reads
        // `value.ttl` and bounds storage time accordingly,
        // so a token with `exp` 10s in the future is
        // evicted in 10s — not at the 300s ceiling.
        // A token with `exp` already past is rejected here
        // (don't cache; an `active=true` + past `exp` is an
        // inconsistent IdP response and a fresh introspect
        // on the next call might recover).
        let ttl = match compute_positive_ttl(body.exp, self.config.max_positive_ttl) {
            Some(ttl) => ttl,
            None => return Err(ValidationError::Malformed),
        };
        let returned = principal.clone();
        self.positive
            .insert(token.to_owned(), CachedPrincipal { principal, ttl })
            .await;
        Ok(returned)
    }
}

/// Compute the positive-cache TTL for a freshly introspected
/// token. Returns `None` when the IdP says the token is
/// already expired (callers surface that as
/// `ValidationError::Malformed` without caching).
///
/// `exp` is RFC 7662 §2.2: integer seconds since Unix epoch.
/// When absent (the IdP doesn't emit `exp`), the cache uses
/// the operator-configured ceiling exactly.
/// Post-`active=true` security
/// invariants the introspection response must satisfy before
/// the principal is built. Returns `false` (caller maps to
/// `Malformed`) when either:
///
/// - `token_type` is present and isn't `"Bearer"`
///   (case-insensitive per RFC 6749 §7.1). Refuses replay
///   of a leaked refresh / device / id-token at `/mcp`.
/// - `expected_audience` is configured AND the response
///   either omits `aud` entirely or carries an `aud` that
///   doesn't include the expected value. Mirrors the JWT
///   validator's `set_audience` (which requires presence,
///   not just non-mismatch) so a misconfigured IdP can't
///   slip a cross-RP token past.
///
/// Both checks are no-ops in their inverse: absent
/// `token_type` is accepted (most IdPs don't emit it), and
/// when `expected_audience` is empty (test fixtures,
/// single-RP IdPs that scope at the endpoint) the `aud`
/// check is skipped entirely.
fn enforce_active_invariants(cfg: &IntrospectionConfig, body: &IntrospectionResponse) -> bool {
    if let Some(tt) = body.token_type.as_deref() {
        if !tt.eq_ignore_ascii_case("Bearer") {
            return false;
        }
    }
    if !cfg.expected_audience.is_empty() {
        let Some(aud) = body.aud.as_ref() else {
            return false;
        };
        if !audience_matches(aud, &cfg.expected_audience) {
            return false;
        }
    }
    true
}

fn compute_positive_ttl(exp_unix: Option<i64>, ceiling: Duration) -> Option<Duration> {
    let Some(exp) = exp_unix else {
        return Some(ceiling);
    };
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let remaining = exp.saturating_sub(now);
    if remaining <= 0 {
        return None;
    }
    let remaining = Duration::from_secs(remaining as u64);
    Some(std::cmp::min(remaining, ceiling))
}

/// RFC 7662 §2.2 response shape. Fields are all optional
/// when `active=false`; when `active=true` the IdP SHOULD
/// emit `sub`, `exp`, `scope`, etc. We tolerate any subset.
#[derive(Debug, Deserialize)]
struct IntrospectionResponse {
    active: bool,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    aud: Option<Value>,
    #[serde(default)]
    exp: Option<i64>,
    /// RFC 7662 §2.2 OPTIONAL `token_type` (e.g. "Bearer").
    /// When present, must be
    /// "Bearer" — refuses refresh-token replay at /mcp.
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
    /// Catch-all for non-standard claims (tenant id, custom
    /// roles, etc.). Serde fills this with everything not
    /// already named above.
    #[serde(flatten)]
    extra: serde_json::Map<String, Value>,
}

fn build_principal(
    cfg: &IntrospectionConfig,
    body: &IntrospectionResponse,
) -> Result<Principal, ValidationError> {
    let sub = body
        .sub
        .clone()
        .ok_or_else(|| ValidationError::Infra("introspection active=true with no sub".into()))?;
    let scopes: Vec<String> = body
        .scope
        .as_deref()
        .map(|s| s.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default();
    let tenant_str = body
        .extra
        .get(&cfg.tenant_claim)
        .and_then(|v| v.as_str())
        .unwrap_or(waygate_core::TenantId::DEFAULT);
    let tenant = waygate_core::TenantId::parse(tenant_str).unwrap_or_default();
    Ok(Principal {
        sub,
        email: body.email.clone(),
        groups: body.groups.clone(),
        issuer: cfg.issuer.clone(),
        scopes,
        tenant,
        auth_method: AuthMethod::Oauth,
        // Opaque tokens don't carry a JWT — the raw token
        // can't be re-signed for RFC 8693 exchange.
        // Upstream identity chaining falls back
        // to the Tier-B (gateway-minted JWT) path for these
        // principals.
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    })
}

fn audience_matches(aud: &Value, expected: &str) -> bool {
    match aud {
        Value::String(s) => s == expected,
        Value::Array(items) => items.iter().any(|v| v.as_str() == Some(expected)),
        _ => false,
    }
}

fn looks_like_jwt(token: &str) -> bool {
    // Three non-empty base64url segments separated by `.`.
    // Also check that each
    // segment is base64url (`A-Z`, `a-z`, `0-9`, `-`, `_`)
    // — without the char check, an opaque token that
    // happens to contain two dots and any non-base64url
    // body (e.g. `foo.bar.b@z`) would be misrouted to the
    // JWT validator and 401 instead of being introspected.
    // The JWT validator does the real cryptographic parse;
    // this filter just routes typed tokens to the right
    // validator.
    let parts: Vec<&str> = token.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && is_base64url(p))
}

fn is_base64url(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_filter_skips_jwts() {
        // Three non-empty base64url segments → JWT shape.
        assert!(looks_like_jwt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig"));
    }

    #[test]
    fn shape_filter_accepts_opaque() {
        // Authentik opaque tokens are alphanumeric.
        assert!(!looks_like_jwt("aBc123xyz789opaqueTOKEN"));
        // Two segments → not JWT.
        assert!(!looks_like_jwt("foo.bar"));
        // Empty segment → not JWT.
        assert!(!looks_like_jwt("foo..bar"));
        assert!(!looks_like_jwt(".bar.baz"));
    }

    #[test]
    fn shape_filter_rejects_three_segments_with_non_base64url_chars() {
        // A token with 3
        // dot-separated segments but non-base64url chars
        // (`@`, `+`, `/`, `=`, whitespace) is NOT a JWT and
        // must skip the JWT validator → introspection
        // gets a shot. Pin every common offender.
        assert!(!looks_like_jwt("foo.bar.b@z"));
        assert!(!looks_like_jwt("foo.bar+baz.qux"));
        assert!(!looks_like_jwt("foo.b/r.baz"));
        assert!(!looks_like_jwt("foo.bar.baz="));
        assert!(!looks_like_jwt("foo. bar.baz"));
        // Base64url-clean three-segment shape IS routed to
        // the JWT validator — that's the right behavior.
        assert!(looks_like_jwt("aaa-bbb_ccc.ddd_eee-fff.ggg"));
    }

    #[test]
    fn audience_check_string() {
        assert!(audience_matches(&serde_json::json!("rs1"), "rs1"));
        assert!(!audience_matches(&serde_json::json!("rs2"), "rs1"));
    }

    #[test]
    fn audience_check_array() {
        assert!(audience_matches(&serde_json::json!(["rs1", "rs2"]), "rs1"));
        assert!(!audience_matches(&serde_json::json!(["rs2", "rs3"]), "rs1"));
    }

    #[test]
    fn audience_check_other_shapes_reject() {
        // RFC 7662 §2.2 says `aud` is string-or-array; any
        // other JSON shape is a malformed introspection
        // response. Treat as no-match so the validator
        // falls through to negative cache.
        assert!(!audience_matches(&serde_json::json!(42), "rs1"));
        assert!(!audience_matches(&serde_json::json!(null), "rs1"));
        assert!(!audience_matches(&serde_json::json!({}), "rs1"));
    }

    fn cfg(tenant_claim: &str) -> IntrospectionConfig {
        IntrospectionConfig {
            introspection_url: "https://idp.example/introspect".into(),
            client_id: "gw".into(),
            client_secret: "s".into(),
            issuer: "https://idp.example".into(),
            expected_audience: "rs1".into(),
            tenant_claim: tenant_claim.into(),
            ..IntrospectionConfig::default()
        }
    }

    fn resp(extra: serde_json::Map<String, Value>) -> IntrospectionResponse {
        IntrospectionResponse {
            active: true,
            sub: Some("alice".into()),
            email: Some("alice@example.test".into()),
            scope: Some("mcp:read mcp:invoke".into()),
            aud: Some(serde_json::json!("rs1")),
            exp: Some(OffsetDateTime::now_utc().unix_timestamp() + 60),
            token_type: Some("Bearer".into()),
            groups: vec!["mcp-users".into()],
            extra,
        }
    }

    #[test]
    fn build_principal_parses_scope_and_groups() {
        let p = build_principal(&cfg("tenant"), &resp(Default::default())).unwrap();
        assert_eq!(p.sub, "alice");
        assert_eq!(p.email.as_deref(), Some("alice@example.test"));
        assert_eq!(p.scopes, vec!["mcp:read", "mcp:invoke"]);
        assert_eq!(p.groups, vec!["mcp-users"]);
        assert_eq!(p.issuer, "https://idp.example");
        assert!(matches!(p.auth_method, AuthMethod::Oauth));
        // Tenant defaults when claim missing.
        assert_eq!(p.tenant, waygate_core::TenantId::default());
    }

    #[test]
    fn build_principal_extracts_tenant_from_configured_claim() {
        let mut extra = serde_json::Map::new();
        extra.insert("tenant".into(), serde_json::json!("acme"));
        let p = build_principal(&cfg("tenant"), &resp(extra)).unwrap();
        assert_eq!(p.tenant.as_str(), "acme");
    }

    #[test]
    fn build_principal_uses_configurable_tenant_claim_name() {
        // A library caller can select the `org` claim explicitly.
        let mut extra = serde_json::Map::new();
        extra.insert("org".into(), serde_json::json!("acme"));
        let p = build_principal(&cfg("org"), &resp(extra)).unwrap();
        assert_eq!(p.tenant.as_str(), "acme");
    }

    #[test]
    fn build_principal_active_without_sub_is_infra_error() {
        // RFC 7662 §2.2: when active=true the IdP SHOULD
        // emit `sub`. Treat its absence as an IdP bug + bubble
        // up as Infra so the middleware surfaces 503 rather
        // than minting a sub-less Principal.
        let mut r = resp(Default::default());
        r.sub = None;
        let err = build_principal(&cfg("tenant"), &r).expect_err("must reject");
        assert!(matches!(err, ValidationError::Infra(_)));
    }

    // Pin that the positive
    // cache TTL is min(exp - now, ceiling) and that an
    // already-past exp is rejected without caching.

    #[test]
    fn positive_ttl_uses_remaining_lifetime_when_shorter_than_ceiling() {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let ttl = compute_positive_ttl(Some(now + 10), Duration::from_secs(300)).expect("some ttl");
        // Should be ~10s (allow 1s slop for the
        // OffsetDateTime::now() inside compute_positive_ttl).
        assert!(
            ttl <= Duration::from_secs(10) && ttl >= Duration::from_secs(8),
            "want ~10s, got {ttl:?}"
        );
    }

    #[test]
    fn positive_ttl_clamps_to_ceiling_when_exp_far_out() {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let ttl =
            compute_positive_ttl(Some(now + 86_400), Duration::from_secs(300)).expect("some ttl");
        // exp - now == 86_400s; ceiling 300s wins.
        assert_eq!(ttl, Duration::from_secs(300));
    }

    #[test]
    fn positive_ttl_defaults_to_ceiling_when_exp_absent() {
        let ttl = compute_positive_ttl(None, Duration::from_secs(300)).expect("some ttl");
        assert_eq!(ttl, Duration::from_secs(300));
    }

    #[test]
    fn positive_ttl_rejects_already_expired_token() {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        assert!(
            compute_positive_ttl(Some(now - 1), Duration::from_secs(300)).is_none(),
            "an active=true response with exp in the past must NOT be cached"
        );
        assert!(
            compute_positive_ttl(Some(now), Duration::from_secs(300)).is_none(),
            "exp == now is also past (remaining = 0); reject"
        );
    }

    // Pin the
    // post-active=true invariants — token_type must be
    // "Bearer" when echoed, and aud must be present +
    // matching when an expected_audience is configured.

    #[test]
    fn active_invariants_accept_default_response() {
        // Baseline: token_type=Bearer, aud=rs1 (configured
        // expected_audience). Should pass.
        assert!(enforce_active_invariants(
            &cfg("tenant"),
            &resp(Default::default())
        ));
    }

    #[test]
    fn active_invariants_accept_absent_token_type() {
        // RFC 7662 §2.2 makes token_type OPTIONAL. Most IdPs
        // (incl. Authentik) don't emit it. Absent → accept.
        let mut r = resp(Default::default());
        r.token_type = None;
        assert!(enforce_active_invariants(&cfg("tenant"), &r));
    }

    #[test]
    fn active_invariants_reject_non_bearer_token_type() {
        // Refuses replay of a leaked refresh / device /
        // id-token as a `/mcp` bearer. Case-insensitive per
        // RFC 6749 §7.1.
        for tt in ["refresh_token", "id_token", "mac", "DPoP", "Refresh"] {
            let mut r = resp(Default::default());
            r.token_type = Some(tt.into());
            assert!(
                !enforce_active_invariants(&cfg("tenant"), &r),
                "token_type {tt:?} must be rejected"
            );
        }
        // Mixed case "Bearer" still accepted.
        for tt in ["bearer", "BEARER", "BeArEr"] {
            let mut r = resp(Default::default());
            r.token_type = Some(tt.into());
            assert!(
                enforce_active_invariants(&cfg("tenant"), &r),
                "token_type {tt:?} must be accepted (case-insensitive Bearer)"
            );
        }
    }

    #[test]
    fn active_invariants_require_aud_when_expected_audience_configured() {
        // Trusting the IdP when `aud` is absent would be a
        // hole. Mirror the JWT validator: a configured
        // expected_audience makes `aud` MANDATORY, so a
        // misconfigured IdP can't slip a cross-RP token in
        // via an active=true + no-aud response.
        let mut r = resp(Default::default());
        r.aud = None;
        assert!(
            !enforce_active_invariants(&cfg("tenant"), &r),
            "active=true with no aud must be rejected when expected_audience is set"
        );
    }

    #[test]
    fn active_invariants_reject_mismatched_aud() {
        let mut r = resp(Default::default());
        r.aud = Some(serde_json::json!("some-other-rp"));
        assert!(!enforce_active_invariants(&cfg("tenant"), &r));
        // Array form: rs1 not in list → reject.
        r.aud = Some(serde_json::json!(["rp-a", "rp-b"]));
        assert!(!enforce_active_invariants(&cfg("tenant"), &r));
    }

    #[test]
    fn active_invariants_accept_aud_array_containing_expected() {
        let mut r = resp(Default::default());
        r.aud = Some(serde_json::json!(["rs1", "rp-b"]));
        assert!(enforce_active_invariants(&cfg("tenant"), &r));
    }

    #[test]
    fn active_invariants_skip_aud_check_when_expected_audience_empty() {
        // Test fixtures + single-RP IdPs that scope at the
        // endpoint: when no expected_audience is configured,
        // missing `aud` is not a problem.
        let mut c = cfg("tenant");
        c.expected_audience = String::new();
        let mut r = resp(Default::default());
        r.aud = None;
        assert!(enforce_active_invariants(&c, &r));
        // And mismatched aud is ignored too.
        r.aud = Some(serde_json::json!("anything"));
        assert!(enforce_active_invariants(&c, &r));
    }

    #[test]
    fn build_principal_drops_raw_token() {
        // Opaque tokens can't be re-signed for RFC 8693
        // token exchange, so we MUST NOT stamp the raw
        // bearer onto Principal.raw_token (Tier-A upstream
        // chaining would otherwise try to use it).
        // Identity chaining falls back to the Tier-B gateway-
        // minted JWT path for these principals.
        let p = build_principal(&cfg("tenant"), &resp(Default::default())).unwrap();
        assert!(p.raw_token.is_none());
    }
}
