//! Runtime config for the gateway-as-AS.
//!
//! All fields are passed in from `waygate-server` at boot; this crate owns no
//! env plumbing itself. Keeps the crate usable from tests that synthesise a
//! config directly.

use std::path::PathBuf;
use std::time::Duration;

use thiserror::Error;

use crate::crypto::UpstreamCrypto;

/// Config for [`crate::build_router`]. Construct via the builder pattern in
/// `waygate-server`'s startup code.
#[derive(Clone)]
pub struct AsConfig {
    /// Gateway's canonical external URL. Used as the `iss` claim on minted
    /// access tokens and as the `issuer` in `/.well-known/oauth-authorization-server`.
    pub public_url: String,
    /// `aud` claim on minted tokens — the resource URL that MCP requests
    /// land on (e.g. `https://gateway.example.com/mcp`).
    pub audience: String,
    /// Upstream OIDC issuer (Authentik). Used for upstream authorize/token hops.
    pub upstream_issuer: String,
    pub upstream_authorize_endpoint: String,
    pub upstream_token_endpoint: String,
    pub upstream_client_id: String,
    pub upstream_client_secret: String,
    /// Gateway-hosted URL that Authentik redirects back to after the upstream
    /// login. Registered as the redirect URI for the gateway's OAuth client
    /// in Authentik.
    pub upstream_redirect_uri: String,
    /// Scopes the gateway requests from Authentik. Typically
    /// `["openid","profile","email","groups"]`.
    pub upstream_scopes: Vec<String>,
    /// AES-256-GCM key used to encrypt upstream access+refresh tokens at rest.
    pub upstream_crypto: UpstreamCrypto,
    /// CIMD allowlist. `None` = any public HTTPS host with a non-root path.
    /// Non-empty = host must match (case-insensitive) one of these entries.
    pub cimd_allowed_hosts: Option<Vec<String>>,
    /// Directory from which the AS serves `/cimd/dev-clients/<name>.json`.
    /// Set for local-dev only — lets a client serve its CIMD document from
    /// the AS's own origin, bypassing the SSRF guard's private-IP check
    /// for LAN-hosted git servers. See `crates/waygate-test-client/docs/cimd-hosting.md`.
    /// `None` disables the route.
    pub cimd_dev_doc_dir: Option<PathBuf>,
    /// TTL of gateway-minted access tokens. Default 1h.
    pub access_token_ttl: Duration,
    /// TTL of refresh tokens. Default 30d.
    pub refresh_token_ttl: Duration,
    /// TTL of the in-flight authorize transaction. Default 15m.
    pub transaction_ttl: Duration,
    /// TTL of an issued gateway auth code. Default 60s (just long enough for
    /// the client to finish the PKCE token round-trip).
    pub code_ttl: Duration,
    /// Allowed OAuth scopes. Any scope request not in this set is rejected.
    pub allowed_scopes: Vec<String>,
    /// Gateway-wide kill switch for the interactive consent screen.
    /// When `true`, the `/oauth/callback` path refuses to mint a code
    /// until a covering `oauth_consent` row exists for
    /// `(tenant_id, principal_sub, client_id)` — if the
    /// row is missing OR the requested scopes aren't a
    /// subset of the granted ones, the callback 302s
    /// the user to `/oauth/consent?token=…` so they can
    /// approve or deny. This setting applies to every tenant.
    pub require_explicit_consent: bool,
    /// EMA (ID-JAG) mint TTL. ID-JAGs are short-lived cross-app hand-offs
    /// (~5 min) — shorter than gateway access tokens. Used by the
    /// `/oauth/token` token-exchange grant. Only consulted when EMA is
    /// wired (see [`crate::EmaDeps`]).
    pub idjag_ttl: Duration,
    /// EMA: require a present + active SCIM row before minting an ID-JAG
    /// (the SCIM-fed IdP-AS posture). When `true`, a principal with no
    /// SCIM directory row cannot obtain an ID-JAG even if Cedar would
    /// otherwise permit — so a deleted/deprovisioned directory entry
    /// (which the tombstone surfaces as inactive) blocks the grant.
    pub idjag_require_scim: bool,
    /// EMA: the Resource-AS issuers an ID-JAG may be `aud`-bound to. The
    /// token-exchange handler refuses (`invalid_target`) to mint for an
    /// `audience` outside this set, so the gateway can't be coaxed into
    /// signing an assertion aimed at an arbitrary Resource-AS. `waygate-server`
    /// seeds it with the gateway's own issuer (Tier-A/B self-redemption) plus
    /// any operator-listed peer issuers (`GATEWAY_AS_IDJAG_AUDIENCES`). Empty
    /// ⇒ no audience is accepted (fail-closed).
    pub idjag_allowed_audiences: Vec<String>,
    /// EMA: the MCP-server resource identifiers an ID-JAG may be issued for.
    /// The mint handler refuses (`invalid_target`) to mint for a `resource`
    /// outside this set, so a caller can't obtain a signed grant for an
    /// arbitrary / unknown upstream. Empty ⇒ no resource is accepted
    /// (fail-closed). `waygate-server` derives it from the
    /// per-upstream resource identifiers in the loaded manifests
    /// (`{public_url}/servers/<name>`), unioned with any operator-listed
    /// extras (`GATEWAY_AS_IDJAG_RESOURCES`, e.g. peer/external mint targets).
    /// NOTE: the redeem path additionally rejects `resource == audience` (the
    /// estate audience) even if listed here — that is the one value that would
    /// mint an unrestricted /mcp token (see `token.rs` redeem step 3b).
    pub idjag_known_resources: Vec<String>,
    /// EMA: issuers whose ID-JAGs the Resource-AS redeem path (`jwt-bearer`
    /// grant) will accept. `waygate-server` seeds it with the gateway's own
    /// issuer (homelab self-redemption) plus operator-listed trusted IdP/peer
    /// issuers (`GATEWAY_AS_TRUSTED_IDP_ISSUERS`). An ID-JAG whose `iss` is
    /// outside this set is rejected. Empty ⇒ no assertion is accepted
    /// (fail-closed).
    pub idjag_trusted_issuers: Vec<String>,
    /// EMA: advertise EMA support in discovery — the
    /// `io.modelcontextprotocol/enterprise-managed-authorization` capability
    /// extension (via `waygate-mcp`) and the ID-JAG grant URNs + grant profile
    /// in this AS's RFC 8414 metadata. Off by default (`GATEWAY_AS_IDJAG_ADVERTISE`)
    /// so a deployment turns it on only after a client is verified — the EMA
    /// grants still *work* when the deps are wired, this only controls whether
    /// they're broadcast in discovery (protecting the working OAuth/API-key path).
    pub idjag_advertise: bool,
}

#[derive(Debug, Error)]
pub enum AsConfigError {
    #[error("public_url must be set")]
    MissingPublicUrl,
    #[error("audience must be set")]
    MissingAudience,
    #[error("upstream_redirect_uri must be absolute https URL")]
    BadRedirectUri,
}

impl AsConfig {
    pub fn validate(&self) -> Result<(), AsConfigError> {
        if self.public_url.is_empty() {
            return Err(AsConfigError::MissingPublicUrl);
        }
        if self.audience.is_empty() {
            return Err(AsConfigError::MissingAudience);
        }
        if !self.upstream_redirect_uri.starts_with("https://")
            && !self.upstream_redirect_uri.starts_with("http://")
        {
            return Err(AsConfigError::BadRedirectUri);
        }
        Ok(())
    }

    /// Absolute URL for a gateway-local path like `/oauth/callback`.
    pub fn absolute(&self, path: &str) -> String {
        format!("{}{}", self.issuer(), path)
    }

    /// Canonical issuer string for this AS.
    ///
    /// This is the single source of truth for the value that must be
    /// byte-identical across:
    ///
    /// 1. The `issuer` field in `/.well-known/oauth-authorization-server`
    ///    (RFC 8414 + OIDC Discovery).
    /// 2. The `iss` parameter on every authorization-response redirect
    ///    (RFC 9207 §2).
    /// 3. The `iss` field on every `/oauth/token` response shape
    ///    (RFC 9207 §3).
    /// 4. The `iss` claim minted into access tokens by
    ///    [`waygate_oidc::IdentityIssuer`].
    ///
    /// RFC 9207 §2.4 requires clients to do an exact string match
    /// between the metadata `issuer` and any received `iss` value. The
    /// canonical form has no trailing slash so that `GATEWAY_PUBLIC_URL=
    /// https://mcp.example/` (operator-supplied with a slash) produces
    /// the same issuer as `https://mcp.example` (without).
    pub fn issuer(&self) -> &str {
        self.public_url.trim_end_matches('/')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(public_url: &str) -> AsConfig {
        AsConfig {
            public_url: public_url.into(),
            audience: "aud".into(),
            upstream_issuer: "x".into(),
            upstream_authorize_endpoint: "x".into(),
            upstream_token_endpoint: "x".into(),
            upstream_client_id: "x".into(),
            upstream_client_secret: "x".into(),
            upstream_redirect_uri: "https://x".into(),
            upstream_scopes: vec![],
            upstream_crypto: UpstreamCrypto::from_key_bytes([0u8; 32]),
            cimd_allowed_hosts: None,
            cimd_dev_doc_dir: None,
            access_token_ttl: Duration::from_secs(60),
            refresh_token_ttl: Duration::from_secs(60),
            transaction_ttl: Duration::from_secs(60),
            code_ttl: Duration::from_secs(60),
            allowed_scopes: vec![],
            require_explicit_consent: false,
            idjag_ttl: Duration::from_secs(300),
            idjag_require_scim: true,
            idjag_allowed_audiences: vec![],
            idjag_known_resources: vec![],
            idjag_trusted_issuers: vec![],
            idjag_advertise: false,
        }
    }

    #[test]
    fn issuer_trims_trailing_slash() {
        // RFC 9207 §2.4: clients exact-string-match `iss` against
        // metadata `issuer`. Both shapes must collapse to the same
        // canonical value.
        assert_eq!(cfg("https://mcp.example/").issuer(), "https://mcp.example");
        assert_eq!(cfg("https://mcp.example").issuer(), "https://mcp.example");
    }

    #[test]
    fn absolute_uses_canonical_issuer() {
        // Pre-fix, `absolute` trimmed inline. Post-fix it delegates to
        // `issuer()`. Verify both shapes still produce the right URL.
        assert_eq!(
            cfg("https://mcp.example/").absolute("/oauth/callback"),
            "https://mcp.example/oauth/callback"
        );
        assert_eq!(
            cfg("https://mcp.example").absolute("/oauth/callback"),
            "https://mcp.example/oauth/callback"
        );
    }
}
