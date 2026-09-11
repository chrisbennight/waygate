//! Gateway-minted identity JWT forwarded to upstream MCP servers.
//!
//! Upstreams on this LAN don't yet speak OAuth. The gateway bridges by minting
//! a short-lived EdDSA-signed JWT per upstream call, carrying the caller's
//! `sub`/`email`/`groups` plus an `act` claim (RFC 8693 §4.1) naming the
//! gateway itself as the actor. Upstreams that want to verify pull the
//! public half from the gateway's `/.well-known/jwks.json`.
//!
//! Ed25519 over EdDSA — small keys, small tokens, no curve-choice footgun.

use std::sync::Arc;
use std::time::Duration;

use axum::response::Json;
use axum::routing::get;
use axum::Router;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::SigningKey;
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, EllipticCurve, Jwk, JwkSet, KeyAlgorithm,
    OctetKeyPairParameters, OctetKeyPairType, PublicKeyUse,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

use crate::jwks::{JwksError, JwksProvider};
use crate::Principal;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("parse Ed25519 PKCS#8 PEM: {0}")]
    ParseKey(String),
    #[error("jwt encode: {0}")]
    Encode(#[from] jsonwebtoken::errors::Error),
}

/// Error from [`verify_id_jag`] / [`verify_id_jag_with_jwks`] (the Resource-AS
/// redeem path).
#[derive(Debug, Error)]
pub enum IdJagVerifyError {
    /// Header `typ` is not [`ID_JAG_TYP`] — a non-ID-JAG token (ID token,
    /// access token, per-upstream identity JWT) was presented as an ID-JAG.
    /// The token-confusion guard (RFC 8725 §3.11); `jsonwebtoken` does not
    /// check `typ` itself.
    #[error("not an ID-JAG: header typ {got:?} != {expected}")]
    WrongTyp {
        got: Option<String>,
        expected: &'static str,
    },
    /// The JOSE header carried no `kid`, so no signing key can be resolved.
    #[error("token header missing `kid`")]
    MissingKid,
    /// JWKS lookup for the header `kid` failed (unknown kid / fetch error).
    #[error("jwks: {0}")]
    Jwks(#[from] JwksError),
    /// Signature / `aud` / `iss` / `exp` validation failed.
    #[error("jwt: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

/// Actor claim (RFC 8693 §4.1) — names the forwarding principal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActClaim {
    pub sub: String,
}

/// The claim set signed by [`IdentityIssuer`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    pub act: ActClaim,
    /// Issuer of the upstream-facing token's *original* subject token (i.e.
    /// Authentik). Not part of RFC 8693 but useful for forensic chains.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_issuer: Option<String>,
}

/// JOSE header `typ` for an ID-JAG, per
/// draft-ietf-oauth-identity-assertion-authz-grant. Set on mint and
/// **verified explicitly** on redeem — `jsonwebtoken::decode` does not
/// check `typ`, so this is the token-confusion guard that stops an
/// ID-JAG from being accepted as an ID token / access token (or vice
/// versa).
pub const ID_JAG_TYP: &str = "oauth-id-jag+jwt";

/// Identity Assertion JWT Authorization Grant (ID-JAG) claim set per
/// draft-ietf-oauth-identity-assertion-authz-grant-04 and the MCP
/// Enterprise-Managed Authorization profile.
///
/// Minted by the gateway in its IdP-Authorization-Server role (RFC 8693
/// token-exchange) and redeemed (RFC 7523 `jwt-bearer`) at the Resource
/// Authorization Server for an audience-restricted access token. The
/// header `typ` MUST be [`ID_JAG_TYP`].
///
/// Required claims (`iss`, `sub`, `aud`, `client_id`, `jti`, `exp`,
/// `iat`) are always serialized. `resource`, `scope`, and `email` are
/// optional in the base draft; this gateway always sets `resource`
/// (the MCP profile audience-restricts the issued token to it) and
/// `client_id` (the redeeming client MUST match it). Authorization
/// groups are deliberately NOT carried here — the Resource AS re-derives
/// them from the authoritative SCIM directory at redeem time rather than
/// trusting a claim in the assertion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdJagClaims {
    /// Unique JWT id — replay defense at the Resource AS.
    pub jti: String,
    /// IdP Authorization Server issuer identifier.
    pub iss: String,
    /// Subject identifier for the end user.
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Resource Authorization Server issuer identifier.
    pub aud: String,
    /// MCP Server resource identifier (RFC 9728). The issued access
    /// token MUST be audience-restricted to this value.
    pub resource: String,
    /// OAuth client id at the Resource AS. The redeeming client MUST
    /// authenticate as this value.
    pub client_id: String,
    pub iat: i64,
    pub exp: i64,
    /// Space-separated requested scopes (RFC 6749 §3.3).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scope: String,
    /// The subject's tenant. Carried so the Resource AS mints the redeemed
    /// access token in the correct tenant — SCIM/RBAC/Cedar facts and audit
    /// attribution are all tenant-scoped, and the bearer validator defaults a
    /// missing tenant to `default`. Skipped on serialize when `None` (default
    /// tenant), matching `AccessTokenClaims.tenant`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

/// Claims for a gateway-minted OAuth 2.1 access token issued to an MCP
/// client. Shape matches what [`crate::BearerValidator`] consumes: `iss`,
/// `aud`, space-separated `scope`, plus `sub`/`email`/`groups` for
/// authorization. No `act` — this is a direct bearer token, not a
/// delegation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    /// Space-separated OAuth scopes (RFC 6749 §3.3). `BearerValidator`
    /// parses both string and array forms.
    pub scope: String,
    /// OAuth client that received this token. Not part of the standard
    /// claim set but useful for audit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// The principal's tenant id, minted onto the gateway access
    /// token so `BearerValidator` can populate `Principal.tenant`
    /// from the JWT `tenant` claim instead of falling back to
    /// `default`. Without this
    /// field, any per-tenant admin holding a gateway-minted
    /// `mcp:admin` token would silently target the `default`
    /// tenant on every admin write — see oauth_consent.rs
    /// (which depends on `principal.tenant` for scoping) and
    /// rate_limit_policies.rs (same pattern). `None` ⇒ caller
    /// is minting a legacy/dev token without a tenant; the
    /// validator's default-fallback kicks in. Skipped on serialize
    /// when None so older verifiers still parse the JWT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

/// Mints short-lived identity tokens and publishes its public key.
pub struct IdentityIssuer {
    signing_key: EncodingKey,
    public_jwk: Jwk,
    /// JWT `kid` header emitted on every minted token.
    pub kid: String,
    /// `iss` claim on minted tokens — the gateway's canonical URL.
    pub issuer: String,
    /// `act.sub` claim — opaque gateway identifier (e.g. `gateway-main`).
    pub gateway_id: String,
    /// How long each minted token stays valid.
    pub ttl: Duration,
}

impl std::fmt::Debug for IdentityIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Intentionally elide `signing_key` — never leak key material into
        // a log line via Debug.
        f.debug_struct("IdentityIssuer")
            .field("kid", &self.kid)
            .field("issuer", &self.issuer)
            .field("gateway_id", &self.gateway_id)
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl IdentityIssuer {
    /// Build an issuer from an Ed25519 PKCS#8 PEM-encoded private key. The
    /// public key is derived from the private (Ed25519 is deterministic), so
    /// callers only provide one file.
    pub fn from_ed25519_pkcs8_pem(
        private_pem: &str,
        kid: impl Into<String>,
        issuer: impl Into<String>,
        gateway_id: impl Into<String>,
        ttl: Duration,
    ) -> Result<Self, IdentityError> {
        let signing = SigningKey::from_pkcs8_pem(private_pem)
            .map_err(|e| IdentityError::ParseKey(e.to_string()))?;
        let x = URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes());

        let signing_key = EncodingKey::from_ed_pem(private_pem.as_bytes())?;
        let kid = kid.into();
        let public_jwk = Jwk {
            common: CommonParameters {
                public_key_use: Some(PublicKeyUse::Signature),
                key_algorithm: Some(KeyAlgorithm::EdDSA),
                key_id: Some(kid.clone()),
                ..Default::default()
            },
            algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
                key_type: OctetKeyPairType::OctetKeyPair,
                curve: EllipticCurve::Ed25519,
                x,
            }),
        };

        Ok(Self {
            signing_key,
            public_jwk,
            kid,
            issuer: issuer.into(),
            gateway_id: gateway_id.into(),
            ttl,
        })
    }

    /// Mint a fresh token for `principal` scoped to `audience` (usually the
    /// upstream server name).
    pub fn mint(&self, principal: &Principal, audience: &str) -> Result<String, IdentityError> {
        let now = OffsetDateTime::now_utc();
        let exp = now + self.ttl;
        let claims = IdentityClaims {
            iss: self.issuer.clone(),
            sub: principal.sub.clone(),
            aud: audience.to_owned(),
            iat: now.unix_timestamp(),
            exp: exp.unix_timestamp(),
            email: principal.email.clone(),
            groups: principal.groups.clone(),
            act: ActClaim {
                sub: self.gateway_id.clone(),
            },
            original_issuer: Some(principal.issuer.clone()),
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());
        Ok(jsonwebtoken::encode(&header, &claims, &self.signing_key)?)
    }

    /// Public-key JWKS document. Serve at `/.well-known/jwks.json`.
    pub fn jwks(&self) -> JwkSet {
        JwkSet {
            keys: vec![self.public_jwk.clone()],
        }
    }

    /// This issuer's published [`Jwk`]. Exposed so
    /// [`IdentityKeyring`] can aggregate JWKs across multiple
    /// issuers without round-tripping each one through a
    /// single-key `jwks()` call.
    pub fn public_jwk(&self) -> &Jwk {
        &self.public_jwk
    }

    /// Mint an OAuth 2.1 access token for the MCP client after a successful
    /// authorization-code exchange. Distinct from [`Self::mint`] — no `act`
    /// claim (this is a direct bearer token, not delegation). `aud` is the
    /// gateway's own resource URL; the gateway's `BearerValidator` verifies
    /// it on every `/mcp` request.
    ///
    /// The `ttl` arg is passed explicitly rather than reusing `self.ttl`
    /// because the identity-JWT TTL is sized for upstream hops (short,
    /// 60s-ish) while access tokens for MCP clients typically live 1h.
    #[allow(clippy::too_many_arguments)]
    pub fn mint_access_token(
        &self,
        sub: &str,
        email: Option<&str>,
        groups: &[String],
        audience: &str,
        scopes: &[String],
        client_id: Option<&str>,
        // Tenant the principal belongs to. Passed through onto
        // `AccessTokenClaims.tenant` so `BearerValidator` can
        // rehydrate `Principal.tenant` instead of falling back to
        // default. `None` ⇒ minted
        // outside an AS-mode flow that knows the tenant (dev /
        // test helpers); the validator's default-fallback kicks in.
        tenant: Option<&str>,
        ttl: Duration,
    ) -> Result<String, IdentityError> {
        let now = OffsetDateTime::now_utc();
        let exp = now + ttl;
        let claims = AccessTokenClaims {
            iss: self.issuer.clone(),
            sub: sub.to_owned(),
            aud: audience.to_owned(),
            iat: now.unix_timestamp(),
            exp: exp.unix_timestamp(),
            email: email.map(str::to_owned),
            groups: groups.to_vec(),
            scope: scopes.join(" "),
            client_id: client_id.map(str::to_owned),
            tenant: tenant.map(str::to_owned),
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());
        Ok(jsonwebtoken::encode(&header, &claims, &self.signing_key)?)
    }

    /// Mint an ID-JAG (Identity Assertion JWT Authorization Grant) for
    /// the gateway's IdP-Authorization-Server role. The caller (the
    /// `/oauth/token` token-exchange handler) is responsible for the
    /// policy decision BEFORE calling this — minting is the side effect.
    ///
    /// `audience` is the Resource AS issuer identifier (the `aud`
    /// claim); `resource` is the MCP Server resource id the issued
    /// access token will be audience-restricted to; `client_id` is the
    /// OAuth client that must authenticate when redeeming. The header
    /// `typ` is [`ID_JAG_TYP`] and a fresh `jti` is stamped for replay
    /// defense at the Resource AS.
    ///
    /// `ttl` is passed explicitly (not `self.ttl`) because ID-JAGs are
    /// short-lived hand-offs (~5 min) — shorter than gateway access
    /// tokens and longer than the per-upstream identity JWT.
    #[allow(clippy::too_many_arguments)]
    pub fn mint_id_jag(
        &self,
        sub: &str,
        email: Option<&str>,
        audience: &str,
        resource: &str,
        client_id: &str,
        scopes: &[String],
        tenant: Option<&str>,
        ttl: Duration,
    ) -> Result<String, IdentityError> {
        let now = OffsetDateTime::now_utc();
        let exp = now + ttl;
        let claims = IdJagClaims {
            jti: crate::pkce::new_random_token(),
            iss: self.issuer.clone(),
            sub: sub.to_owned(),
            email: email.map(str::to_owned),
            aud: audience.to_owned(),
            resource: resource.to_owned(),
            client_id: client_id.to_owned(),
            iat: now.unix_timestamp(),
            exp: exp.unix_timestamp(),
            scope: scopes.join(" "),
            tenant: tenant.map(str::to_owned),
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());
        // Explicit typing (RFC 8725 §3.11) — the redeem path checks this.
        header.typ = Some(ID_JAG_TYP.to_owned());
        Ok(jsonwebtoken::encode(&header, &claims, &self.signing_key)?)
    }
}

/// Verify an ID-JAG presented for redemption at the Resource AS (RFC 7523
/// `jwt-bearer`). Returns the decoded [`IdJagClaims`] when the assertion is a
/// well-formed, in-date ID-JAG signed by a trusted issuer for `expected_aud`.
///
/// Checks, in order:
/// 1. Header `typ ==` [`ID_JAG_TYP`] — the token-confusion guard.
///    `jsonwebtoken` does NOT inspect `typ`, so without this an ID token /
///    access token / per-upstream identity JWT signed by the same key could be
///    redeemed as an ID-JAG.
/// 2. EdDSA signature against `key`, `aud == expected_aud`, `iss ∈
///    trusted_issuers`, and `exp` (30 s leeway) — via
///    [`jsonwebtoken::Validation`]. `Validation::new(EdDSA)` also pins the
///    algorithm, closing the alg-confusion vector.
///
/// The caller still enforces the two EMA MUSTs the assertion can't self-prove:
/// single-use `jti` (the replay store) and `client_id ==` the authenticated
/// redeeming client.
pub fn verify_id_jag(
    token: &str,
    key: &jsonwebtoken::DecodingKey,
    expected_aud: &str,
    trusted_issuers: &[String],
) -> Result<IdJagClaims, IdJagVerifyError> {
    let header = jsonwebtoken::decode_header(token)?;
    if header.typ.as_deref() != Some(ID_JAG_TYP) {
        return Err(IdJagVerifyError::WrongTyp {
            got: header.typ,
            expected: ID_JAG_TYP,
        });
    }
    let mut v = jsonwebtoken::Validation::new(Algorithm::EdDSA);
    let issuers: Vec<&str> = trusted_issuers.iter().map(String::as_str).collect();
    v.set_issuer(&issuers);
    v.set_audience(&[expected_aud]);
    v.leeway = 30;
    let data = jsonwebtoken::decode::<IdJagClaims>(token, key, &v)?;
    Ok(data.claims)
}

/// [`verify_id_jag`] with key resolution: extract the header `kid`, look up the
/// matching public key in `jwks`, then verify. This is the entry point the
/// Resource-AS redeem handler calls — it keeps the kid→key plumbing (and the
/// `jsonwebtoken` header parse) inside `waygate-oidc` so callers needn't depend
/// on it. The token-confusion `typ` guard is enforced by [`verify_id_jag`].
pub async fn verify_id_jag_with_jwks(
    token: &str,
    jwks: &Arc<JwksProvider>,
    expected_aud: &str,
    trusted_issuers: &[String],
) -> Result<IdJagClaims, IdJagVerifyError> {
    let header = jsonwebtoken::decode_header(token)?;
    let kid = header.kid.ok_or(IdJagVerifyError::MissingKid)?;
    let key = jwks.decoding_key(&kid).await?;
    verify_id_jag(token, &key, expected_aud, trusted_issuers)
}

/// Peek the unverified `iss` claim from a JWT, for **routing only** —
/// e.g. deciding whether to verify an ID-JAG against the local keyring (self
/// issuer) or a peer's JWKS (federated issuer). The signature is NOT checked
/// here: a forged `iss` merely routes the token to a keyset that will fail to
/// verify it, so this can never grant access on its own (the same iss-first
/// routing rationale as `waygate-federation`'s peer validator). Returns `None`
/// when the token is not a three-segment JWT, the payload is not base64url JSON,
/// or it carries no non-empty string `iss`.
pub fn peek_unverified_issuer(token: &str) -> Option<String> {
    let payload_b64 = token.split('.').nth(1)?;
    let raw = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    let iss = value.get("iss")?.as_str()?;
    (!iss.is_empty()).then(|| iss.to_owned())
}

pub type SharedIdentityIssuer = Arc<IdentityIssuer>;

/// Multi-key support for JWKS rotation.
///
/// The keyring publishes EVERY known key in the JWKS document
/// so upstream verifiers can validate tokens signed under any
/// kid in the keyring. Signing always uses the **active**
/// issuer (the one operators rotated into).
///
/// Rotation playbook:
///
///   1. Generate a new keypair, mount the PEM, and add its
///      kid+path to `GATEWAY_IDENTITY_JWT_KEYS`. Restart.
///      Both kids now appear in `/.well-known/jwks.json`;
///      upstream verifiers that cache the JWKS pick up the
///      new kid on their next refresh, but no token is
///      signed under it yet — verify side warms up safely.
///   2. After upstream JWKS caches have refreshed (e.g.
///      `2× max(cache_ttl)` across the network), flip
///      `GATEWAY_IDENTITY_JWT_ACTIVE` to the new kid and
///      restart. Newly minted tokens use the new key;
///      tokens issued before the flip continue to verify
///      because the old key is still in the JWKS.
///   3. After every old-key token has expired, drop the old
///      kid from the keys list and restart. The JWKS now
///      only carries the new key. "Every old-key token" is
///      `max(identity_ttl, access_token_ttl)` because the
///      same keyring signs BOTH the short-lived per-upstream
///      identity JWT (default 60s) AND the gateway-minted
///      OAuth access token (default 3600s = 1h, configured
///      via `state.config.access_token_ttl` in `waygate-as`).
///      Pulling the kid too early 401s still-valid access
///      tokens — the retirement window is the max of BOTH
///      TTLs, not just the identity TTL.
///
/// A keyring of one is the default — single-key deployments
/// boot via [`IdentityKeyring::single`] and behave
/// identically to the single-key surface (same JWKS shape,
/// same active issuer).
///
/// Invariants enforced at construction:
///
/// - The active issuer is required (no empty keyring).
/// - Verify-only JWKs must each carry a `kid` and must not
///   collide with the active issuer's kid or with each
///   other.
///
/// Security: inactive rotation kids carry only the public
/// JWK, NOT a full `IdentityIssuer` with an in-memory
/// private signing key.
/// The previous shape held an `Arc<IdentityIssuer>` per kid
/// — every one of them allocated an `EncodingKey` from the
/// private PEM. A process-memory dump or a careless trace
/// would therefore expose the private material of inactive
/// keys that the gateway never actually signs with. Verify-
/// only kids contribute exactly what the JWKS verifier
/// needs (the public JWK) and nothing more.
#[derive(Debug)]
pub struct IdentityKeyring {
    active: SharedIdentityIssuer,
    /// Verify-only kids (no private signing material loaded).
    /// Stored in stable kid-ascending order so the published
    /// JWKS document is byte-identical across restarts.
    verify_only: Vec<Jwk>,
}

#[derive(Debug, Error)]
pub enum KeyringError {
    /// The keyring constructor takes the active issuer as a
    /// separate (non-optional) argument, so an `ActiveMissing`
    /// / `Empty` case is unrepresentable by construction.
    /// `DuplicateKid` is the only remaining failure mode —
    /// a verify-only JWK's kid collides with the active
    /// issuer's kid, or two verify-only JWKs carry the
    /// same kid. Operators see this string in the boot log
    /// when the multi-key env passes a duplicate.
    #[error("duplicate kid `{0}` in keyring")]
    DuplicateKid(String),
}

impl IdentityKeyring {
    /// Single-key keyring — the shape single-key deployments
    /// boot with. The issuer's kid is both active and the
    /// only key advertised in JWKS.
    pub fn single(issuer: SharedIdentityIssuer) -> Self {
        Self {
            active: issuer,
            verify_only: Vec::new(),
        }
    }

    /// Multi-key keyring. `active` is the signer (the only
    /// kid carrying private key material in memory);
    /// `verify_only_jwks` carry only the public material —
    /// they appear in the published JWKS so unexpired
    /// pre-rotation tokens still verify, but the gateway
    /// process never holds an [`EncodingKey`] for them.
    ///
    /// Non-active keys are constructively narrowed to
    /// public-only: rather than a `Vec<SharedIdentityIssuer>`
    /// that would build a full signing-capable issuer per kid,
    /// this constructor takes bare verify-only JWKs.
    /// Operators using
    /// [`pub_jwk_from_ed25519_pkcs8_pem`] feed the same
    /// PKCS#8 PEM file shape they were already mounting for
    /// signing — the helper derives the public JWK and
    /// discards the private bytes before return.
    pub fn new(
        active: SharedIdentityIssuer,
        verify_only_jwks: Vec<Jwk>,
    ) -> Result<Self, KeyringError> {
        let mut seen = std::collections::HashSet::new();
        seen.insert(active.kid.clone());
        // Sort verify-only kids ascending for deterministic
        // JWKS output (active is always emitted first).
        let mut verify_only: Vec<Jwk> = Vec::with_capacity(verify_only_jwks.len());
        for jwk in verify_only_jwks {
            let kid = jwk
                .common
                .key_id
                .clone()
                .ok_or_else(|| KeyringError::DuplicateKid("<no-kid>".into()))?;
            if !seen.insert(kid.clone()) {
                return Err(KeyringError::DuplicateKid(kid));
            }
            verify_only.push(jwk);
        }
        verify_only.sort_by(|a, b| {
            a.common
                .key_id
                .as_deref()
                .unwrap_or("")
                .cmp(b.common.key_id.as_deref().unwrap_or(""))
        });
        Ok(Self {
            active,
            verify_only,
        })
    }

    /// The issuer used for signing. Hot-path callers
    /// (`mint`, `mint_access_token`) go through this.
    pub fn active(&self) -> &SharedIdentityIssuer {
        &self.active
    }

    /// Aggregated JWKS — active first, then verify-only
    /// kids in ascending order.
    pub fn jwks(&self) -> JwkSet {
        let mut keys: Vec<Jwk> = Vec::with_capacity(1 + self.verify_only.len());
        keys.push(self.active.public_jwk().clone());
        keys.extend(self.verify_only.iter().cloned());
        JwkSet { keys }
    }

    /// Operator-facing introspection. Returns kids in JWKS
    /// publication order (active first). Useful for boot
    /// logs and dashboard rendering.
    pub fn kids(&self) -> Vec<String> {
        let mut out = Vec::with_capacity(1 + self.verify_only.len());
        out.push(self.active.kid.clone());
        out.extend(
            self.verify_only
                .iter()
                .filter_map(|j| j.common.key_id.clone()),
        );
        out
    }

    /// How many keys are in the keyring (active + verify-only).
    pub fn len(&self) -> usize {
        1 + self.verify_only.len()
    }

    /// Always `false` — the keyring is constructed with an
    /// active issuer, so it can never be empty. Kept for
    /// idiomatic guard style at call sites.
    pub fn is_empty(&self) -> bool {
        false
    }
}

/// Derive an Ed25519 public-key JWK from a PKCS#8 PEM
/// private key WITHOUT holding the private material in
/// memory beyond what's needed to compute the public
/// component. The intermediate [`SigningKey`] is dropped at
/// the end of this function (no [`EncodingKey`] is ever
/// constructed).
///
/// Use this for the verify-only kids in an
/// [`IdentityKeyring`] — operators don't need a separate
/// public-key file format; the same PEM they were already
/// mounting for signing is parsed and discarded down to
/// just the JWK.
///
/// Security: building a full [`IdentityIssuer`] for every
/// kid would keep every inactive private key live in the
/// process for the duration of the rotation window; this
/// helper derives the public JWK and discards the private
/// bytes instead.
pub fn pub_jwk_from_ed25519_pkcs8_pem(
    private_pem: &str,
    kid: impl Into<String>,
) -> Result<Jwk, IdentityError> {
    let signing = SigningKey::from_pkcs8_pem(private_pem)
        .map_err(|e| IdentityError::ParseKey(e.to_string()))?;
    let x = URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes());
    // `signing` falls out of scope at end-of-function;
    // no `EncodingKey` constructed.
    Ok(Jwk {
        common: CommonParameters {
            public_key_use: Some(PublicKeyUse::Signature),
            key_algorithm: Some(KeyAlgorithm::EdDSA),
            key_id: Some(kid.into()),
            ..Default::default()
        },
        algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
            key_type: OctetKeyPairType::OctetKeyPair,
            curve: EllipticCurve::Ed25519,
            x,
        }),
    })
}

pub type SharedIdentityKeyring = Arc<IdentityKeyring>;

/// Canonical well-known path for the gateway's public JWKS.
pub const JWKS_PATH: &str = "/.well-known/jwks.json";

/// Router that serves the JWKS document at [`JWKS_PATH`].
///
/// Accepts an [`IdentityKeyring`] so a multi-key (rotating)
/// deployment publishes every key the gateway might have
/// signed a still-valid token under. Single-key deployments
/// wrap their `IdentityIssuer` via
/// [`IdentityKeyring::single`].
pub fn jwks_router<S>(keyring: SharedIdentityKeyring) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new().route(
        JWKS_PATH,
        get({
            let keyring = keyring.clone();
            move || async move { Json(keyring.jwks()) }
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};

    fn test_issuer(ttl: Duration) -> IdentityIssuer {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pem = sk.to_pkcs8_pem(LineEnding::LF).expect("pem");
        IdentityIssuer::from_ed25519_pkcs8_pem(
            &pem,
            "gw-2026-04",
            "https://gateway.example.com",
            "gateway-main",
            ttl,
        )
        .expect("build issuer")
    }

    fn test_principal() -> Principal {
        Principal {
            sub: "user-123".into(),
            email: Some("u@example.test".into()),
            groups: vec!["mcp-users".into(), "mcp-admins".into()],
            issuer: "https://idp.example.com/application/o/mcp-gateway/".into(),
            scopes: vec!["mcp:invoke".into()],
            tenant: waygate_core::TenantId::default(),
            auth_method: crate::AuthMethod::Oauth,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        }
    }

    #[test]
    fn mint_and_verify_roundtrip() {
        let issuer = test_issuer(Duration::from_secs(60));
        let token = issuer.mint(&test_principal(), "example-messages").unwrap();

        let header = decode_header(&token).unwrap();
        assert_eq!(header.alg, Algorithm::EdDSA);
        assert_eq!(header.kid.as_deref(), Some("gw-2026-04"));

        let jwks = issuer.jwks();
        let jwk = &jwks.keys[0];
        let key = DecodingKey::from_jwk(jwk).expect("decode key from jwk");

        let mut v = Validation::new(Algorithm::EdDSA);
        v.set_issuer(&["https://gateway.example.com"]);
        v.set_audience(&["example-messages"]);
        let data = decode::<IdentityClaims>(&token, &key, &v).expect("verify token");

        let c = data.claims;
        assert_eq!(c.iss, "https://gateway.example.com");
        assert_eq!(c.sub, "user-123");
        assert_eq!(c.aud, "example-messages");
        assert_eq!(c.email.as_deref(), Some("u@example.test"));
        assert_eq!(c.groups, vec!["mcp-users".to_string(), "mcp-admins".into()]);
        assert_eq!(c.act.sub, "gateway-main");
        assert_eq!(
            c.original_issuer.as_deref(),
            Some("https://idp.example.com/application/o/mcp-gateway/"),
        );
        assert!(c.exp > c.iat);
    }

    #[test]
    fn rejects_wrong_audience() {
        let issuer = test_issuer(Duration::from_secs(60));
        let token = issuer.mint(&test_principal(), "example-messages").unwrap();
        let jwks = issuer.jwks();
        let key = DecodingKey::from_jwk(&jwks.keys[0]).unwrap();

        let mut v = Validation::new(Algorithm::EdDSA);
        v.set_issuer(&["https://gateway.example.com"]);
        v.set_audience(&["example-observability"]);
        let err = decode::<IdentityClaims>(&token, &key, &v).expect_err("wrong aud");
        assert!(matches!(
            err.kind(),
            jsonwebtoken::errors::ErrorKind::InvalidAudience
        ));
    }

    #[test]
    fn jwks_has_expected_shape() {
        let issuer = test_issuer(Duration::from_secs(60));
        let jwks = issuer.jwks();
        assert_eq!(jwks.keys.len(), 1);
        let jwk = &jwks.keys[0];
        assert_eq!(jwk.common.key_id.as_deref(), Some("gw-2026-04"));
        assert_eq!(jwk.common.key_algorithm, Some(KeyAlgorithm::EdDSA));
        match &jwk.algorithm {
            AlgorithmParameters::OctetKeyPair(okp) => {
                assert_eq!(okp.curve, EllipticCurve::Ed25519);
                // Ed25519 public keys are exactly 32 raw bytes → 43 base64url
                // chars with no padding.
                assert_eq!(okp.x.len(), 43);
                assert!(!okp.x.contains('='));
            }
            other => panic!("wrong algorithm params: {other:?}"),
        }
    }

    #[test]
    fn round_trip_json_jwks() {
        // Serializing and reparsing the JWKS must still yield a usable key —
        // this is what clients actually do.
        let issuer = test_issuer(Duration::from_secs(60));
        let jwks_json = serde_json::to_string(&issuer.jwks()).unwrap();
        let reparsed: JwkSet = serde_json::from_str(&jwks_json).unwrap();
        let key = DecodingKey::from_jwk(&reparsed.keys[0]).expect("decode from roundtrip");

        let token = issuer.mint(&test_principal(), "example-messages").unwrap();
        let mut v = Validation::new(Algorithm::EdDSA);
        v.set_issuer(&["https://gateway.example.com"]);
        v.set_audience(&["example-messages"]);
        decode::<IdentityClaims>(&token, &key, &v).expect("verify via roundtripped jwks");
    }

    #[test]
    fn mint_id_jag_has_typ_and_claims() {
        let issuer = test_issuer(Duration::from_secs(300));
        let token = issuer
            .mint_id_jag(
                "user-123",
                Some("u@example.test"),
                "https://gateway.example.com",
                "https://gateway.example.com/servers/example-observability",
                "https://claude.ai/mcp.json",
                &["mcp:invoke".into(), "mcp:read".into()],
                Some("acme-prod"),
                Duration::from_secs(300),
            )
            .unwrap();

        // typ MUST be oauth-id-jag+jwt — the token-confusion guard.
        let header = decode_header(&token).unwrap();
        assert_eq!(header.alg, Algorithm::EdDSA);
        assert_eq!(header.kid.as_deref(), Some("gw-2026-04"));
        assert_eq!(header.typ.as_deref(), Some("oauth-id-jag+jwt"));

        let jwks = issuer.jwks();
        let key = DecodingKey::from_jwk(&jwks.keys[0]).unwrap();
        let mut v = Validation::new(Algorithm::EdDSA);
        v.set_issuer(&["https://gateway.example.com"]);
        v.set_audience(&["https://gateway.example.com"]);
        let c = decode::<IdJagClaims>(&token, &key, &v).unwrap().claims;
        assert!(
            !c.jti.is_empty(),
            "ID-JAG MUST carry a jti for replay defense"
        );
        assert_eq!(c.sub, "user-123");
        assert_eq!(c.aud, "https://gateway.example.com");
        assert_eq!(
            c.resource,
            "https://gateway.example.com/servers/example-observability"
        );
        assert_eq!(c.client_id, "https://claude.ai/mcp.json");
        assert_eq!(c.email.as_deref(), Some("u@example.test"));
        assert_eq!(c.scope, "mcp:invoke mcp:read");
        assert_eq!(
            c.tenant.as_deref(),
            Some("acme-prod"),
            "the subject's tenant MUST be carried so redeem mints in the right tenant",
        );
        assert!(c.exp > c.iat);
    }

    #[test]
    fn id_jag_jti_is_unique_per_mint() {
        let issuer = test_issuer(Duration::from_secs(60));
        let mint = || {
            issuer
                .mint_id_jag(
                    "s",
                    None,
                    "https://gateway.example.com",
                    "r",
                    "c",
                    &[],
                    None,
                    Duration::from_secs(60),
                )
                .unwrap()
        };
        let key = DecodingKey::from_jwk(&issuer.jwks().keys[0]).unwrap();
        let mut v = Validation::new(Algorithm::EdDSA);
        v.set_issuer(&["https://gateway.example.com"]);
        v.set_audience(&["https://gateway.example.com"]);
        let c1 = decode::<IdJagClaims>(&mint(), &key, &v).unwrap().claims;
        let c2 = decode::<IdJagClaims>(&mint(), &key, &v).unwrap().claims;
        assert_ne!(c1.jti, c2.jti, "each ID-JAG mint must carry a unique jti");
    }

    // ---- verify_id_jag (Resource-AS redeem path) ----

    const TRUSTED: &str = "https://gateway.example.com";

    fn decoding_key(issuer: &IdentityIssuer) -> DecodingKey {
        DecodingKey::from_jwk(&issuer.jwks().keys[0]).expect("decoding key from jwks")
    }

    #[test]
    fn verify_id_jag_roundtrips_a_minted_assertion() {
        let issuer = test_issuer(Duration::from_secs(300));
        let token = issuer
            .mint_id_jag(
                "user-123",
                Some("u@example.test"),
                TRUSTED,
                "https://gateway.example.com/servers/example-observability",
                "https://claude.ai/mcp.json",
                &["mcp:invoke".into()],
                None,
                Duration::from_secs(300),
            )
            .unwrap();
        let claims = verify_id_jag(&token, &decoding_key(&issuer), TRUSTED, &[TRUSTED.into()])
            .expect("a freshly minted ID-JAG must verify");
        assert_eq!(claims.sub, "user-123");
        assert_eq!(
            claims.resource,
            "https://gateway.example.com/servers/example-observability"
        );
        assert_eq!(claims.client_id, "https://claude.ai/mcp.json");
        assert_eq!(claims.scope, "mcp:invoke");
    }

    #[test]
    fn verify_id_jag_rejects_token_without_idjag_typ() {
        // `mint` produces a per-upstream identity JWT with no `typ` header —
        // the token-confusion case verify_id_jag must reject before trusting
        // any claim. (Same key, so only the typ guard — not the signature —
        // distinguishes it.)
        let issuer = test_issuer(Duration::from_secs(300));
        let not_an_idjag = issuer.mint(&test_principal(), TRUSTED).unwrap();
        let err = verify_id_jag(
            &not_an_idjag,
            &decoding_key(&issuer),
            TRUSTED,
            &[TRUSTED.into()],
        )
        .expect_err("a token without the ID-JAG typ must be rejected");
        assert!(matches!(err, IdJagVerifyError::WrongTyp { .. }));
    }

    #[test]
    fn verify_id_jag_rejects_wrong_audience() {
        let issuer = test_issuer(Duration::from_secs(300));
        let token = issuer
            .mint_id_jag(
                "s",
                None,
                TRUSTED,
                "r",
                "c",
                &[],
                None,
                Duration::from_secs(300),
            )
            .unwrap();
        let err = verify_id_jag(
            &token,
            &decoding_key(&issuer),
            "https://other-resource-as.example",
            &[TRUSTED.into()],
        )
        .expect_err("an ID-JAG for a different Resource-AS audience must be rejected");
        assert!(matches!(err, IdJagVerifyError::Jwt(_)));
    }

    #[test]
    fn verify_id_jag_rejects_untrusted_issuer() {
        let issuer = test_issuer(Duration::from_secs(300));
        let token = issuer
            .mint_id_jag(
                "s",
                None,
                TRUSTED,
                "r",
                "c",
                &[],
                None,
                Duration::from_secs(300),
            )
            .unwrap();
        let err = verify_id_jag(
            &token,
            &decoding_key(&issuer),
            TRUSTED,
            &["https://untrusted-idp.example".into()],
        )
        .expect_err("an ID-JAG from an untrusted issuer must be rejected");
        assert!(matches!(err, IdJagVerifyError::Jwt(_)));
    }

    #[test]
    fn verify_id_jag_rejects_expired_assertion() {
        // Hand-craft an ID-JAG whose exp is well in the past, signed by the
        // same key the issuer's JWKS publishes — so only the exp check (not the
        // signature or typ) fails.
        let issuer = test_issuer(Duration::from_secs(300));
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pem = sk.to_pkcs8_pem(LineEnding::LF).unwrap();
        let enc = EncodingKey::from_ed_pem(pem.as_bytes()).unwrap();
        let now = OffsetDateTime::now_utc();
        let claims = IdJagClaims {
            jti: "jti-expired".into(),
            iss: TRUSTED.into(),
            sub: "s".into(),
            email: None,
            aud: TRUSTED.into(),
            resource: "r".into(),
            client_id: "c".into(),
            iat: (now - Duration::from_secs(600)).unix_timestamp(),
            exp: (now - Duration::from_secs(300)).unix_timestamp(),
            scope: String::new(),
            tenant: None,
        };
        let mut h = Header::new(Algorithm::EdDSA);
        h.kid = Some("gw-2026-04".into());
        h.typ = Some(ID_JAG_TYP.to_owned());
        let token = jsonwebtoken::encode(&h, &claims, &enc).unwrap();
        let err = verify_id_jag(&token, &decoding_key(&issuer), TRUSTED, &[TRUSTED.into()])
            .expect_err("an expired ID-JAG must be rejected");
        assert!(matches!(err, IdJagVerifyError::Jwt(_)));
    }

    #[test]
    fn mint_access_token_has_no_act_claim() {
        let issuer = test_issuer(Duration::from_secs(60));
        let token = issuer
            .mint_access_token(
                "user-123",
                Some("u@example.test"),
                &["mcp-users".into()],
                "https://gateway.example.com/mcp",
                &["mcp:invoke".into(), "mcp:read".into()],
                Some("https://claude.ai/mcp.json"),
                None,
                Duration::from_secs(3600),
            )
            .unwrap();

        let jwks = issuer.jwks();
        let key = DecodingKey::from_jwk(&jwks.keys[0]).unwrap();
        let mut v = Validation::new(Algorithm::EdDSA);
        v.set_issuer(&["https://gateway.example.com"]);
        v.set_audience(&["https://gateway.example.com/mcp"]);
        let data = decode::<AccessTokenClaims>(&token, &key, &v).unwrap();

        assert_eq!(data.claims.sub, "user-123");
        assert_eq!(data.claims.scope, "mcp:invoke mcp:read");
        assert_eq!(
            data.claims.client_id.as_deref(),
            Some("https://claude.ai/mcp.json")
        );

        // The raw JSON must not contain `"act"` — the validator won't reject
        // it, but downstream audit code keys off its absence to distinguish
        // direct bearer tokens from delegated ones.
        let parts: Vec<&str> = token.split('.').collect();
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1].as_bytes())
            .unwrap();
        let body = String::from_utf8(payload).unwrap();
        assert!(
            !body.contains("\"act\""),
            "access token leaked act claim: {body}"
        );
    }

    #[test]
    fn invalid_pem_surfaces_parse_error() {
        let err = IdentityIssuer::from_ed25519_pkcs8_pem(
            "-----BEGIN PRIVATE KEY-----\nnot-real\n-----END PRIVATE KEY-----\n",
            "kid",
            "iss",
            "gw",
            Duration::from_secs(1),
        )
        .expect_err("bad pem");
        assert!(matches!(err, IdentityError::ParseKey(_)));
    }

    // Keyring rotation pins. The keyring is a thin wrapper
    // but the invariants (active must be present, kids unique,
    // JWKS aggregates) are the load-bearing operator-facing
    // surface.

    fn keyed_issuer(seed: u8, kid: &str) -> SharedIdentityIssuer {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pem = sk.to_pkcs8_pem(LineEnding::LF).expect("pem");
        Arc::new(
            IdentityIssuer::from_ed25519_pkcs8_pem(
                &pem,
                kid,
                "https://gateway.example.com",
                "gateway-main",
                Duration::from_secs(60),
            )
            .expect("issuer"),
        )
    }

    #[test]
    fn keyring_single_publishes_one_jwk_and_signs_with_it() {
        let issuer = keyed_issuer(1, "only");
        let kr = IdentityKeyring::single(issuer);
        assert_eq!(kr.kids(), vec!["only".to_owned()]);
        assert_eq!(kr.jwks().keys.len(), 1);
        assert_eq!(kr.active().kid, "only");
    }

    fn pub_jwk(seed: u8, kid: &str) -> Jwk {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pem = sk.to_pkcs8_pem(LineEnding::LF).expect("pem");
        pub_jwk_from_ed25519_pkcs8_pem(&pem, kid).expect("pub jwk")
    }

    #[test]
    fn keyring_multi_signs_with_active_publishes_all() {
        // Active issuer v2 (full); verify-only v1 + v3
        // (public JWK only). JWKS must emit all three.
        let v2 = keyed_issuer(2, "v2");
        let kr = IdentityKeyring::new(v2.clone(), vec![pub_jwk(1, "v1"), pub_jwk(3, "v3")])
            .expect("new");
        assert_eq!(kr.active().kid, "v2");
        // Active first, then verify-only kids ascending.
        assert_eq!(kr.kids(), vec!["v2", "v1", "v3"]);
        let jwks = kr.jwks();
        assert_eq!(jwks.keys.len(), 3);
        // A token signed by the active issuer must verify
        // against the active's JWK from the aggregated set.
        let token = kr
            .active()
            .mint(&test_principal(), "example-messages")
            .unwrap();
        let active_jwk = jwks
            .keys
            .iter()
            .find(|j| j.common.key_id.as_deref() == Some("v2"))
            .expect("active jwk must be in jwks");
        let key = DecodingKey::from_jwk(active_jwk).unwrap();
        let mut v = Validation::new(Algorithm::EdDSA);
        v.set_issuer(&["https://gateway.example.com"]);
        v.set_audience(&["example-messages"]);
        decode::<IdentityClaims>(&token, &key, &v).expect("verify under active jwk");
    }

    #[test]
    fn keyring_rejects_duplicate_kids() {
        // Verify-only JWK shares the active's kid.
        let err = IdentityKeyring::new(keyed_issuer(1, "v1"), vec![pub_jwk(2, "v1")])
            .expect_err("dup kid");
        assert!(matches!(err, KeyringError::DuplicateKid(k) if k == "v1"));
    }

    #[test]
    fn keyring_single_has_no_verify_only_keys() {
        // is_empty() always false; len() = 1; kids = [active].
        let kr = IdentityKeyring::single(keyed_issuer(1, "only"));
        assert_eq!(kr.len(), 1);
        assert!(!kr.is_empty());
        assert_eq!(kr.kids(), vec!["only"]);
        assert_eq!(kr.jwks().keys.len(), 1);
    }

    #[test]
    fn keyring_rotation_old_kid_still_verifies() {
        // Rotation: v1 was active when token was minted;
        // operator added v2 and flipped active. v1 is now
        // a verify-only kid in the keyring. The post-
        // rotation JWKS must still verify the v1-signed
        // token. v1 here is a public-only JWK — the test
        // specifically uses the narrower verify-only shape to
        // prove rotation works without retaining the v1
        // private key in process memory.
        let v1_signer = keyed_issuer(1, "v1");
        let token = v1_signer
            .mint(&test_principal(), "example-messages")
            .unwrap();

        // Active v2 (full issuer) + v1 as a verify-only JWK.
        // Match the byte content via the same seed.
        let v1_jwk_public = pub_jwk(1, "v1");
        let kr = IdentityKeyring::new(keyed_issuer(2, "v2"), vec![v1_jwk_public]).unwrap();

        let jwks = kr.jwks();
        let v1_jwk = jwks
            .keys
            .iter()
            .find(|j| j.common.key_id.as_deref() == Some("v1"))
            .expect("v1 jwk still present after rotation");
        let key = DecodingKey::from_jwk(v1_jwk).unwrap();
        let mut v = Validation::new(Algorithm::EdDSA);
        v.set_issuer(&["https://gateway.example.com"]);
        v.set_audience(&["example-messages"]);
        decode::<IdentityClaims>(&token, &key, &v).expect("pre-rotation token still verifies");
    }

    #[test]
    fn pub_jwk_helper_drops_private_key_material() {
        // The helper must derive the public component
        // without surfacing the private. We can only
        // observe the absence by checking the returned
        // type — Jwk doesn't carry the PEM — but pin the
        // happy path so a future refactor that returns
        // (Jwk, EncodingKey) gets caught.
        let jwk = pub_jwk(7, "narrow");
        assert_eq!(jwk.common.key_id.as_deref(), Some("narrow"));
        match jwk.algorithm {
            AlgorithmParameters::OctetKeyPair(ref okp) => {
                assert_eq!(okp.curve, EllipticCurve::Ed25519);
                assert_eq!(okp.x.len(), 43); // Ed25519 32 bytes → 43 base64url chars
            }
            _ => panic!("unexpected algorithm params"),
        }
    }
}
