//! Bearer-chain validator for Tier-C peer assertions.
//!
//! Once a peer is registered ([`crate`]) and its JWKS is warm
//! in the cache ([`crate::jwks`]), this validator turns an
//! `Authorization: Bearer <jwt>` whose `iss` matches a
//! registered `federated_peers.issuer` into a [`Principal`]
//! with `auth_method = PeerAssertion` and `tenant` taken from
//! the *peer's* registered tenant — not from the JWT.
//!
//! ## Why iss-first lookup is safe
//!
//! We base64-decode the JWT payload to peek `iss` BEFORE
//! verifying the signature, then use that as the cache key.
//! That sounds like trusting unverified data, but it's only
//! used to *route* — the actual decision still rests on the
//! signature check that runs against the peer's cached JWKS.
//! A forged JWT with `iss` = some-real-peer fails signature
//! verification, because the attacker doesn't hold that
//! peer's private key. The routing key is essentially a hint
//! that says "which key bundle to check this against."
//!
//! ## What this file does NOT do
//!
//! - Per-upstream `tier_c_peer:<peer_id>` outbound identity
//!   selection (minting an assertion to send to a peer).
//!   Inbound verification (this file) and outbound minting
//!   (`waygate_upstream::pool::session_identity`) are
//!   separate pathways.
//! - Trust-tier-driven principal shape: today both `Full` and
//!   `Restricted` peers produce identical principals (sub +
//!   issuer + tenant). Restricted-tier wrapping
//!   (`peer:<peer_id>`-style sub rewrite, suppression of the
//!   original user identity) lands later. The migration's
//!   `trust_tier` column stays advisory for now and the
//!   validator records it on the principal-attribution
//!   tracing field so operators can see which tier accepted
//!   the call.

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{decode, jwk::AlgorithmParameters, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use thiserror::Error;

use waygate_oidc::header_validator::HeaderValidator;
use waygate_oidc::validator::ValidationError;
use waygate_oidc::{AuthMethod, Principal};

use crate::jwks::{CachedJwks, SharedPeerJwksCache};

/// Scope-prefix denylist applied to scopes claimed by
/// peer-asserted JWTs. A peer can attest ANY scope string in
/// their token, but we MUST NOT honor admin / SCIM-write
/// scopes on a peer-asserted principal — the local admin /
/// SCIM surfaces are gated by
/// `principal.has_scope(...)` and would otherwise let a
/// registered peer mint operator access on the peer record's
/// tenant. Match is by literal prefix:
///
/// - `mcp:admin` and any future `mcp:admin:*`
/// - `scim:write` (read-only SCIM via `scim:read` is fine for
///   directory lookups but the write surface mints / modifies
///   users)
///
/// Tier-A and OAuth principals are unaffected — this filter
/// only fires inside `PeerJwtValidator::validate_inner`.
const PEER_FORBIDDEN_SCOPE_PREFIXES: &[&str] = &["mcp:admin", "scim:write"];

fn filter_peer_scopes(scopes: Vec<String>) -> Vec<String> {
    scopes
        .into_iter()
        .filter(|s| {
            !PEER_FORBIDDEN_SCOPE_PREFIXES
                .iter()
                .any(|forbidden| s == forbidden || s.starts_with(&format!("{forbidden}:")))
        })
        .collect()
}

/// Internal-only error surface — converted to
/// [`ValidationError`] at the trait boundary. Granular so the
/// peer-attribution tracing field can be populated even on
/// rejection without re-parsing the JWT.
#[derive(Debug, Error)]
enum PeerValidationError {
    #[error("missing Authorization header")]
    Missing,
    #[error("malformed Authorization header (expected `Bearer <token>`)")]
    Malformed,
    /// Header parsed cleanly but the token body is not a
    /// JWT-shaped `xxx.yyy.zzz`. Treated as client error.
    #[error("token is not a JWT (missing dot-separated segments)")]
    NotJwt,
    /// `iss` claim missing, non-string, or empty. Routed to
    /// the chain's next validator — a token with no `iss`
    /// isn't a peer assertion, by definition.
    #[error("token payload missing or invalid `iss` claim")]
    NoIssuer,
    /// `iss` is well-formed but doesn't match any cached
    /// peer. Surfaced as `UnknownKid`-flavored client error
    /// so the bearer middleware falls through to the next
    /// validator (oauth, api-key, etc.) rather than blocking.
    #[error("no registered peer matches issuer `{issuer}`")]
    NoPeer { issuer: String },
    /// kid present in the JWT header but not in any peer's
    /// cached JWKS for the matched issuer. Same client-error
    /// fall-through behaviour as `NoPeer`.
    #[error("no peer key matches kid `{kid}` for issuer `{issuer}`")]
    NoKey { issuer: String, kid: String },
    /// jsonwebtoken decode failed (bad sig, expired, audience
    /// mismatch, etc.). Surfaced as JWT-class so the
    /// middleware reports the OAuth-shaped error.
    #[error("jwt: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    /// Base64 / JSON decode of the payload chunk failed.
    /// Doesn't survive the segment check, so this only fires
    /// on malformed-but-three-segment input. Client error.
    #[error("payload decode failed: {0}")]
    PayloadDecode(String),
    /// Two or more cached entries for the same issuer can
    /// verify the same JWT (the migration's
    /// `UNIQUE(tenant_id, issuer)` permits this). Returning
    /// whichever HashMap-order candidate is iterated first
    /// would leak the choice into `principal.tenant` in a
    /// way that isn't deterministic across runs. Fail-closed:
    /// refuse the token and force the operator to pick a
    /// single tenant registration. Listed peers (peer_id
    /// values) are kept on the error for the audit row but
    /// not for the response body — the bearer middleware
    /// converts this to a generic JWT error.
    #[error("peer assertion is ambiguous: {tenants:?} can all verify (this gateway requires explicit tenant binding for federated calls)")]
    Ambiguous { tenants: Vec<String> },
}

impl From<PeerValidationError> for ValidationError {
    fn from(e: PeerValidationError) -> Self {
        match e {
            PeerValidationError::Missing => ValidationError::Missing,
            PeerValidationError::Malformed | PeerValidationError::NotJwt => {
                ValidationError::Malformed
            }
            PeerValidationError::Jwt(j) => ValidationError::Jwt(j),
            // No-peer / no-key / bad-payload all fall through
            // to the next validator. We surface as a `Jwt`
            // ValidationError with InvalidToken kind because
            // `ValidationError::Malformed` is reserved for
            // pre-token rejections and the bearer middleware's
            // `is_client_error` returns true for `Jwt(_)`.
            PeerValidationError::NoIssuer
            | PeerValidationError::NoPeer { .. }
            | PeerValidationError::NoKey { .. }
            | PeerValidationError::PayloadDecode(_)
            | PeerValidationError::Ambiguous { .. } => ValidationError::Jwt(
                jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken),
            ),
        }
    }
}

/// Validator that maps a peer-asserted JWT to a [`Principal`].
/// Holds shared (cheap-to-clone via Arc) cache + audience
/// state; cloning the validator does NOT clone the cache.
pub struct PeerJwtValidator {
    cache: SharedPeerJwksCache,
    /// Expected `aud` claim. Same value as the OIDC validator's
    /// audience — the public URL of this gateway. A peer that
    /// emits a token for a different audience won't accidentally
    /// be accepted here.
    audience: String,
    /// Accepted signing algorithms. Defaults mirror the OAuth
    /// validator's allowlist: RS256/RS512/ES256/EdDSA. Operators
    /// can narrow via [`Self::with_algorithms`] when they want
    /// to force a single algorithm.
    algorithms: Vec<Algorithm>,
    /// Acceptable clock skew, in seconds. Defaults to 30s —
    /// same as `BearerValidator`.
    leeway: u64,
}

impl PeerJwtValidator {
    pub fn new(cache: SharedPeerJwksCache, audience: impl Into<String>) -> Self {
        Self {
            cache,
            audience: audience.into(),
            algorithms: vec![
                Algorithm::RS256,
                Algorithm::RS512,
                Algorithm::ES256,
                Algorithm::EdDSA,
            ],
            leeway: 30,
        }
    }

    pub fn with_algorithms(mut self, algs: Vec<Algorithm>) -> Self {
        self.algorithms = algs;
        self
    }

    /// Strip the `Bearer ` prefix + dispatch to [`Self::validate_token`].
    /// Public so other crates (smoke tests, dashboard probes)
    /// can drive the validator with a bare token value.
    pub async fn validate_token(&self, token: &str) -> Result<Principal, ValidationError> {
        self.validate_inner(token).await.map_err(Into::into)
    }

    async fn validate_inner(&self, token: &str) -> Result<Principal, PeerValidationError> {
        // 1. Peek `iss` from the payload chunk without
        //    verifying the signature. The peek is routing
        //    only: the chosen JWKS still has to validate the
        //    signature, so a forged iss simply fails sig
        //    verification rather than gaining access.
        let issuer = peek_issuer(token)?;

        // 2. Lookup. An iss with no cached peer falls through
        //    to the next validator — this is the "token isn't
        //    for me" branch.
        let candidates = self.cache.get_by_issuer(&issuer).await;
        if candidates.is_empty() {
            return Err(PeerValidationError::NoPeer { issuer });
        }

        // 3. Decode the header to pick the right kid + alg.
        //    Header decode does not verify the signature; it
        //    just parses the JOSE header.
        let header = jsonwebtoken::decode_header(token)?;
        if !self.algorithms.contains(&header.alg) {
            return Err(PeerValidationError::Jwt(jsonwebtoken::errors::Error::from(
                jsonwebtoken::errors::ErrorKind::InvalidAlgorithm,
            )));
        }
        let kid = header.kid.clone().ok_or_else(|| {
            PeerValidationError::Jwt(jsonwebtoken::errors::Error::from(
                jsonwebtoken::errors::ErrorKind::InvalidToken,
            ))
        })?;

        // 4. For each candidate peer record (same iss can be
        //    registered in multiple tenants), find a JWK that
        //    matches the kid and try to verify the signature.
        //
        //    Do NOT short-circuit on the first candidate that
        //    owns the kid — a same-issuer-multi-tenant
        //    deployment can have DIFFERENT keys under the
        //    same kid. Iterate all candidates; on decode
        //    failure stash the error and try the next.
        //
        //    When MULTIPLE candidates' JWKS verify the SAME
        //    token (same issuer + same key registered in
        //    different tenants — the migration's
        //    UNIQUE(tenant_id, issuer) permits this), the
        //    choice of tenant attribution would leak HashMap
        //    iteration order into `principal.tenant`.
        //    Fail-closed: collect every passing candidate's
        //    tenant id, and if the set has more than one
        //    member, refuse the token. Operators have to
        //    register the peer in exactly one tenant to use
        //    federation calls.
        let mut last_jwt_err: Option<jsonwebtoken::errors::Error> = None;
        let mut accepted: Vec<(&CachedJwks, Claims)> = Vec::new();
        for candidate in &candidates {
            let Some(jwk) = candidate.keys.find(&kid) else {
                continue;
            };
            let key = match &jwk.algorithm {
                AlgorithmParameters::RSA(p) => match DecodingKey::from_rsa_components(&p.n, &p.e) {
                    Ok(k) => k,
                    Err(e) => {
                        last_jwt_err = Some(e);
                        continue;
                    }
                },
                AlgorithmParameters::EllipticCurve(p) => {
                    match DecodingKey::from_ec_components(&p.x, &p.y) {
                        Ok(k) => k,
                        Err(e) => {
                            last_jwt_err = Some(e);
                            continue;
                        }
                    }
                }
                AlgorithmParameters::OctetKeyPair(p) => {
                    match DecodingKey::from_ed_components(&p.x) {
                        Ok(k) => k,
                        Err(e) => {
                            last_jwt_err = Some(e);
                            continue;
                        }
                    }
                }
                // OKP (Ed25519) and EC / RSA cover the four
                // algorithms in `self.algorithms`. HMAC/oct is
                // intentionally unsupported — a federated peer
                // signing with a shared secret would be a
                // credential-sharing anti-pattern. Skip this
                // candidate; another candidate's key for the
                // same kid might still be a supported family.
                AlgorithmParameters::OctetKey(_) => {
                    last_jwt_err = Some(jsonwebtoken::errors::Error::from(
                        jsonwebtoken::errors::ErrorKind::InvalidAlgorithm,
                    ));
                    continue;
                }
            };

            // jsonwebtoken's Validation requires every alg in
            // `algorithms` to match the key family — narrow to
            // the header alg (already vetted against the
            // allowlist above).
            let mut v = Validation::new(header.alg);
            v.set_issuer(&[issuer.as_str()]);
            v.set_audience(&[self.audience.as_str()]);
            v.leeway = self.leeway;

            match decode::<Claims>(token, &key, &v) {
                Ok(d) => {
                    accepted.push((candidate.as_ref(), d.claims));
                }
                Err(e) => {
                    tracing::debug!(
                        peer_id = %candidate.peer_id,
                        peer_tenant = %candidate.tenant_id,
                        kid = %kid,
                        error = %e,
                        "peer-asserted JWT decode failed for candidate; trying next",
                    );
                    last_jwt_err = Some(e);
                }
            };
        }

        if accepted.is_empty() {
            // Every candidate failed. If at least one had the
            // kid and we tried it, surface the last decode
            // error so the bearer middleware reports the
            // OAuth-shaped error rather than a kid-not-found
            // fall-through — distinguishing "we tried to
            // verify and failed" from "this token was never
            // routable to a peer" matters for the caller's
            // error class.
            if let Some(e) = last_jwt_err {
                return Err(PeerValidationError::Jwt(e));
            }
            return Err(PeerValidationError::NoKey { issuer, kid });
        }

        // If more than one candidate verified, the
        // principal.tenant attribution would depend on
        // iteration order. Refuse ambiguous tokens rather than
        // mint a non-deterministic principal. The legitimate
        // single-key, single-tenant-registration case still
        // works because `accepted.len() == 1`. The ambiguous
        // case forces operator-side disambiguation (delete
        // duplicate registrations, or wait for the spec to
        // define tenant-binding claims).
        let unique_tenants: std::collections::BTreeSet<&str> =
            accepted.iter().map(|(c, _)| c.tenant_id.as_str()).collect();
        if unique_tenants.len() > 1 {
            let tenants: Vec<String> = unique_tenants.iter().map(|s| (*s).to_owned()).collect();
            tracing::warn!(
                ?tenants,
                issuer = %issuer,
                "peer-asserted JWT verified against multiple tenants — refusing ambiguous attribution",
            );
            return Err(PeerValidationError::Ambiguous { tenants });
        }

        // Exactly one tenant; accept the first (any) candidate
        // whose key verified — they all share the same tenant
        // attribution so the choice is non-leaky.
        let (candidate, c) = accepted.into_iter().next().expect("non-empty just checked");
        let tenant = waygate_core::TenantId::parse(&candidate.tenant_id).unwrap_or_default();

        // A peer can attest ANY scope claim on their JWT, but
        // we MUST NOT honor admin/SCIM-write scopes on a
        // peer-asserted principal — the local admin/SCIM
        // surfaces are gated by `principal.has_scope(...)`
        // and would otherwise let a registered peer mint
        // operator access on the peer record's tenant. Filter
        // the claimed scope list against the
        // [`PEER_FORBIDDEN_SCOPE_PREFIXES`] denylist so a
        // peer's call only ever projects user-level scopes
        // (mcp:invoke*, mcp:read) into the local request.
        let scopes = filter_peer_scopes(c.scope.clone());

        tracing::debug!(
            peer_id = %candidate.peer_id,
            peer_tenant = %candidate.tenant_id,
            issuer = %candidate.issuer,
            trust_tier = candidate.trust_tier.as_str(),
            sub = %c.sub,
            scopes_kept = scopes.len(),
            scopes_dropped = c.scope.len() - scopes.len(),
            "peer-asserted JWT accepted",
        );

        Ok(Principal {
            sub: c.sub,
            email: c.email,
            groups: c.groups,
            issuer: c.iss,
            scopes,
            tenant,
            auth_method: AuthMethod::PeerAssertion,
            // PeerAssertion principals do NOT carry
            // `raw_token`. The upstream pool's RFC 8693
            // exchange path
            // (`waygate_upstream::pool::preflight_exchange`)
            // uses `principal.raw_token` as the subject
            // token when no stored OAuth session exists,
            // and we MUST NOT let an inbound peer JWT
            // become the subject of an outbound token
            // exchange against an upstream IdP — that's a
            // separate outbound-identity-chaining concern,
            // and accidentally exposing it here would mean
            // any tier-A upstream call from a
            // peer-asserted principal would silently
            // forward the peer's JWT to the IdP. Leaving
            // this `None` keeps the OAuth + peer paths
            // categorically separate; the `tier_c_peer:`
            // selector (`waygate_upstream::identity_client`)
            // mints a brand-new gateway-signed JWT for
            // outbound calls instead.
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        })
    }
}

#[async_trait]
impl HeaderValidator for PeerJwtValidator {
    async fn validate_header(&self, header: &str) -> Result<Principal, ValidationError> {
        let token = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))
            .ok_or(PeerValidationError::Malformed)?;
        if token.is_empty() {
            return Err(PeerValidationError::Missing.into());
        }
        self.validate_token(token).await
    }
}

/// Build a `DecodingKey` from a peer JWK for **ID-JAG
/// verification**, which is **EdDSA-only**. This is narrower than the general
/// peer-bearer path ([`PeerJwtValidator::validate_inner`], which accepts
/// RSA/EC/EdDSA via `Validation::new(header.alg)`): an ID-JAG is verified by
/// [`waygate_oidc::verify_id_jag`], which pins `Algorithm::EdDSA` — matching the
/// gateway's own ID-JAGs (the keyring mints EdDSA, and self-redeem verifies
/// EdDSA). So peer ID-JAGs must also be Ed25519-signed; an RSA/EC peer key
/// would only ever fail in `verify_id_jag` anyway, so we reject it here for an
/// honest "this key family is unusable for ID-JAG" result instead of letting
/// a bogus `DecodingKey` construction succeed only to fail confusingly later.
/// Broadening ID-JAG verification to RSA/EC would be a deliberate change to
/// `verify_id_jag`'s algorithm allow-list, not a silent capability of this
/// builder. HMAC/oct is rejected outright (shared-secret peer = anti-pattern).
fn peer_decoding_key(
    jwk: &jsonwebtoken::jwk::Jwk,
) -> Result<DecodingKey, jsonwebtoken::errors::Error> {
    match &jwk.algorithm {
        AlgorithmParameters::OctetKeyPair(p) => DecodingKey::from_ed_components(&p.x),
        // RSA / EC / oct are not valid ID-JAG signing families for this gateway.
        AlgorithmParameters::RSA(_)
        | AlgorithmParameters::EllipticCurve(_)
        | AlgorithmParameters::OctetKey(_) => Err(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidAlgorithm,
        )),
    }
}

/// A peer-minted ID-JAG verified against the peer's cached
/// JWKS, with the tenant attribution THIS gateway registered the peer under.
#[derive(Debug, Clone)]
pub struct PeerIdJag {
    /// The verified ID-JAG claims (typ / aud / iss / exp / signature checked).
    pub claims: waygate_oidc::IdJagClaims,
    /// Tenant from the local `federated_peers` record for the peer — **not** the
    /// ID-JAG's `tenant` claim. A peer must not be able to pick our tenant; the
    /// receiving gateway decides which of its tenants a peer's calls land in
    /// (see `docs/agents/federation.md`).
    pub tenant: waygate_core::TenantId,
    /// The matched peer's id, for audit attribution.
    pub peer_id: uuid::Uuid,
}

/// Error surface for [`verify_peer_id_jag`].
#[derive(Debug, Error)]
pub enum PeerIdJagError {
    /// Payload `iss` missing/invalid — not a peer assertion.
    #[error("token payload missing or invalid `iss` claim")]
    NoIssuer,
    /// `iss` matched no registered peer in the JWKS cache.
    #[error("no registered peer matches issuer `{issuer}`")]
    NoPeer { issuer: String },
    /// No peer key matched the header `kid` (or the header was malformed).
    #[error("no peer key matches the token for issuer `{issuer}`")]
    NoKey { issuer: String },
    /// Header parse failed (missing kid, unsupported alg shape).
    #[error("jwt header invalid: {0}")]
    Header(jsonwebtoken::errors::Error),
    /// A candidate key was found but verification (typ / aud / iss / exp / sig)
    /// failed. Carries the last such failure.
    #[error("peer ID-JAG verification failed: {0}")]
    Verify(waygate_oidc::IdJagVerifyError),
    /// More than one tenant's peer record verified the same assertion — the
    /// tenant attribution would be non-deterministic. Fail closed (mirrors the
    /// `PeerJwtValidator` ambiguity guard); the operator must register the peer
    /// in exactly one tenant.
    #[error("peer ID-JAG is ambiguous across tenants: {tenants:?}")]
    Ambiguous { tenants: Vec<String> },
}

/// Verify an ID-JAG **minted by a peer gateway** against that
/// peer's cached JWKS, returning the claims plus the tenant THIS gateway has the
/// peer registered under.
///
/// Routing is iss-first (peek the unverified `iss` to pick the candidate peer
/// records), but the decision rests on the signature: a forged `iss` simply
/// fails verification because the attacker doesn't hold the peer's key. For each
/// candidate the kid-matched key is run through [`waygate_oidc::verify_id_jag`],
/// which enforces the ID-JAG `typ` (token-confusion guard), `aud` (= this
/// gateway), `iss` ∈ `trusted_issuers`, `exp`, and the signature. The peer's
/// `iss` must therefore be in BOTH `federated_peers` (registered) AND
/// `trusted_issuers` (trusted for redeem) — defense in depth.
///
/// Tenant is taken from the matched peer record, never the assertion. If more
/// than one tenant's record verifies the assertion, the call fails closed
/// (`Ambiguous`) rather than leak iteration order into the attribution.
pub async fn verify_peer_id_jag(
    cache: &SharedPeerJwksCache,
    token: &str,
    expected_aud: &str,
    trusted_issuers: &[String],
) -> Result<PeerIdJag, PeerIdJagError> {
    let issuer = peek_issuer(token).map_err(|_| PeerIdJagError::NoIssuer)?;
    let candidates = cache.get_by_issuer(&issuer).await;
    if candidates.is_empty() {
        return Err(PeerIdJagError::NoPeer { issuer });
    }
    let header = jsonwebtoken::decode_header(token).map_err(PeerIdJagError::Header)?;
    let kid = header.kid.clone().ok_or_else(|| {
        PeerIdJagError::Header(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidToken,
        ))
    })?;

    // Per-candidate: find the kid'd key, verify the full ID-JAG. Collect every
    // candidate that verifies so we can fail closed on a multi-tenant match,
    // exactly like `PeerJwtValidator::validate_inner`.
    let mut last_verify_err: Option<waygate_oidc::IdJagVerifyError> = None;
    let mut accepted: Vec<(&CachedJwks, waygate_oidc::IdJagClaims)> = Vec::new();
    for candidate in &candidates {
        let Some(jwk) = candidate.keys.find(&kid) else {
            continue;
        };
        let key = match peer_decoding_key(jwk) {
            Ok(k) => k,
            Err(_) => continue,
        };
        match waygate_oidc::verify_id_jag(token, &key, expected_aud, trusted_issuers) {
            Ok(claims) => accepted.push((candidate.as_ref(), claims)),
            Err(e) => last_verify_err = Some(e),
        }
    }

    if accepted.is_empty() {
        return match last_verify_err {
            Some(e) => Err(PeerIdJagError::Verify(e)),
            None => Err(PeerIdJagError::NoKey { issuer }),
        };
    }

    let unique_tenants: std::collections::BTreeSet<&str> =
        accepted.iter().map(|(c, _)| c.tenant_id.as_str()).collect();
    if unique_tenants.len() > 1 {
        return Err(PeerIdJagError::Ambiguous {
            tenants: unique_tenants.iter().map(|s| (*s).to_owned()).collect(),
        });
    }

    let (candidate, claims) = accepted.into_iter().next().expect("non-empty just checked");
    let tenant = waygate_core::TenantId::parse(&candidate.tenant_id).unwrap_or_default();
    Ok(PeerIdJag {
        claims,
        tenant,
        peer_id: candidate.peer_id,
    })
}

/// Claims we actually consume — same shape as the OAuth
/// validator's, minus the `tenant` claim (peer principals
/// inherit `tenant` from the peer record, not from the JWT).
#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default, deserialize_with = "crate::peer_jwt::deser_scope")]
    scope: Vec<String>,
    #[serde(default)]
    groups: Vec<String>,
}

/// Light-weight `iss`-only payload peek. Avoids pulling in
/// the full claims parser by deserializing into a stub.
#[derive(Deserialize)]
struct IssOnly {
    iss: Option<String>,
}

fn peek_issuer(token: &str) -> Result<String, PeerValidationError> {
    let mut parts = token.split('.');
    let _header = parts.next().ok_or(PeerValidationError::NotJwt)?;
    let payload = parts.next().ok_or(PeerValidationError::NotJwt)?;
    let _sig = parts.next().ok_or(PeerValidationError::NotJwt)?;
    if parts.next().is_some() {
        return Err(PeerValidationError::NotJwt);
    }
    let raw = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| PeerValidationError::PayloadDecode(e.to_string()))?;
    let parsed: IssOnly = serde_json::from_slice(&raw)
        .map_err(|e| PeerValidationError::PayloadDecode(e.to_string()))?;
    let iss = parsed.iss.unwrap_or_default();
    if iss.is_empty() {
        return Err(PeerValidationError::NoIssuer);
    }
    Ok(iss)
}

/// Local copy of the OAuth validator's scope-claim parser so
/// the peer module doesn't need to expose `waygate-oidc`'s
/// crate-private function. Accepts space-separated string or
/// JSON array.
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
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

    fn make_token(payload: &serde_json::Value) -> String {
        let header = serde_json::json!({"alg": "RS256", "kid": "test-kid"});
        let h = B64.encode(header.to_string());
        let p = B64.encode(payload.to_string());
        let s = B64.encode("fake-sig-not-verified-here");
        format!("{h}.{p}.{s}")
    }

    #[test]
    fn peek_issuer_returns_iss() {
        let t = make_token(&serde_json::json!({"iss": "https://peer.example/"}));
        assert_eq!(peek_issuer(&t).unwrap(), "https://peer.example/");
    }

    #[test]
    fn peek_issuer_rejects_missing() {
        let t = make_token(&serde_json::json!({"sub": "alice"}));
        assert!(matches!(
            peek_issuer(&t),
            Err(PeerValidationError::NoIssuer)
        ));
    }

    #[test]
    fn peek_issuer_rejects_empty_string() {
        let t = make_token(&serde_json::json!({"iss": ""}));
        assert!(matches!(
            peek_issuer(&t),
            Err(PeerValidationError::NoIssuer)
        ));
    }

    #[test]
    fn peek_issuer_rejects_non_jwt_shape() {
        assert!(matches!(
            peek_issuer("two.parts"),
            Err(PeerValidationError::NotJwt)
        ));
        assert!(matches!(
            peek_issuer("a.b.c.d"),
            Err(PeerValidationError::NotJwt)
        ));
    }

    #[test]
    fn peek_issuer_rejects_garbage_payload() {
        // Valid b64 but not JSON.
        let header = B64.encode("{\"alg\":\"RS256\"}");
        let payload = B64.encode("not json at all");
        let sig = B64.encode("sig");
        let t = format!("{header}.{payload}.{sig}");
        assert!(matches!(
            peek_issuer(&t),
            Err(PeerValidationError::PayloadDecode(_))
        ));
    }

    #[test]
    fn malformed_header_rejected_before_token_lookup() {
        let cache =
            std::sync::Arc::new(crate::jwks::InMemoryPeerJwksCache::new()) as SharedPeerJwksCache;
        let v = PeerJwtValidator::new(cache, "https://gw.example/");
        let err = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(v.validate_header("not-a-bearer"))
            .unwrap_err();
        match err {
            ValidationError::Malformed => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn bearer_with_empty_token_is_missing() {
        let cache =
            std::sync::Arc::new(crate::jwks::InMemoryPeerJwksCache::new()) as SharedPeerJwksCache;
        let v = PeerJwtValidator::new(cache, "https://gw.example/");
        let err = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(v.validate_header("Bearer "))
            .unwrap_err();
        match err {
            ValidationError::Missing => {}
            other => panic!("expected Missing, got {other:?}"),
        }
    }
}
