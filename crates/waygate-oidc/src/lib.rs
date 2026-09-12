//! OAuth 2.1 resource-server + OIDC primitives for the gateway.
//!
//! The public surface is:
//! * [`Principal`] — authenticated caller distilled from a JWT
//! * [`BearerValidator`] — stateless token validator backed by [`JwksProvider`]
//! * [`middleware::require_bearer`] — axum layer that 401s missing/invalid tokens
//! * [`metadata::ResourceMetadata`] and [`metadata::router`] — RFC 9728
//!   `/.well-known/oauth-protected-resource` surface

use serde::{Deserialize, Serialize};

pub mod aead;
pub mod enricher;
pub mod header_validator;
pub mod id_token;
pub mod identity_jwt;
pub mod introspection;
pub mod jwks;
pub mod metadata;
pub mod middleware;
pub mod pkce;
pub mod session;
pub mod token_exchange;
pub mod upstream_crypto;
pub mod upstream_session;
pub mod validator;

pub use enricher::PrincipalEnricher;
pub use header_validator::HeaderValidator;
pub use id_token::{IdTokenAssurance, IdTokenError, IdTokenValidator};
pub use identity_jwt::{
    jwks_router, peek_unverified_issuer, pub_jwk_from_ed25519_pkcs8_pem, verify_id_jag,
    verify_id_jag_with_jwks, AccessTokenClaims, ActClaim, IdJagClaims, IdJagVerifyError,
    IdentityClaims, IdentityError, IdentityIssuer, IdentityKeyring, KeyringError,
    SharedIdentityIssuer, SharedIdentityKeyring, ID_JAG_TYP, JWKS_PATH,
};
pub use introspection::{IntrospectionConfig, OpaqueTokenValidator};
pub use jwks::{JwksError, JwksProvider};
pub use metadata::ResourceMetadata;
pub use middleware::{AuthAttemptOutcome, AuthAttemptRecorder, AuthMode, BearerLayer};
pub use pkce::{
    authorize_url, exchange_code, new_pkce_pair, new_random_token, refresh_access_token,
    AuthorizeParams, ExchangeParams, OidcEndpoints, PkcePair, RefreshParams, TokenError,
    TokenResponse,
};
pub use session::{
    build_cookie, clear_cookie, cookie_value, decrypt as session_decrypt,
    encrypt as session_encrypt, LoginState, Session, SessionAssurance, SessionError, SessionKey,
    LOGIN_STATE_COOKIE, SESSION_COOKIE,
};
pub use token_exchange::{
    subject_fingerprint, ExchangeError, ExchangeRequest, ExchangedToken, TokenCache,
    TokenExchangeClient, ACCESS_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE,
};
pub use validator::{BearerValidator, ValidationError};

/// How a [`Principal`] was authenticated. Surfaces into Cedar entity attrs
/// so policies can selectively gate tools to one method — e.g.
/// `principal.auth_method == "oauth"` to forbid API-key callers from a
/// step-up-sensitive tool. Default is `Oauth` to keep legacy code paths
/// unchanged when the field is missing on deserialization.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// Token validated as a JWT against an OAuth/OIDC issuer (Authentik or
    /// the gateway's own AS).
    #[default]
    Oauth,
    /// `Authorization: Bearer mcpgw_<secret>` validated against the
    /// `api_keys` table by `waygate-apikeys`.
    ApiKey,
    /// A JWT signed by a registered Tier-C
    /// federated peer (an entry in `federated_peers` whose
    /// `iss` matches the token's `iss` claim and whose cached
    /// JWKS signs the token). Produced by
    /// `waygate_federation::PeerJwtValidator`. Cedar policies
    /// can gate peer-federated calls with
    /// `principal.auth_method == "peer_assertion"`.
    PeerAssertion,
}

impl AuthMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            AuthMethod::Oauth => "oauth",
            AuthMethod::ApiKey => "api_key",
            AuthMethod::PeerAssertion => "peer_assertion",
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Principal {
    pub sub: String,
    pub email: Option<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    pub issuer: String,
    pub scopes: Vec<String>,
    /// Tenant this principal belongs to. Populated by the bearer
    /// validator from the literal `tenant` JWT claim. API-key principals take
    /// their tenant from the `api_keys.tenant_id` row column.
    /// Absent or invalid claim → default tenant.
    ///
    /// Single-tenant deployments and dev mode never see anything
    /// other than `TenantId::DEFAULT`. Multi-tenant deployments
    /// flip on the SCIM/RBAC machinery that consults this field
    /// for every authorization, audit, and storage decision.
    #[serde(default)]
    pub tenant: waygate_core::TenantId,
    /// How this principal was authenticated. Defaults to `Oauth` for
    /// backward compatibility with stored sessions that predate the field.
    #[serde(default)]
    pub auth_method: AuthMethod,
    /// Raw incoming bearer access token that produced this principal. Populated
    /// by [`validator::BearerValidator`] for use with RFC 8693 token exchange;
    /// elided from serde (never cross a storage or log boundary) and from
    /// `Debug` so it can't accidentally end up in a `tracing::debug!` call.
    ///
    /// Only set for OAuth-issued tokens — API-key principals leave this `None`
    /// so token-exchange paths don't accidentally try to swap an API key for
    /// an upstream token.
    #[serde(skip, default)]
    pub raw_token: Option<String>,
    /// SCIM attributes resolved from the gateway's
    /// `scim_users` + `scim_user_groups` + `scim_groups` tables at
    /// bearer-validate time by a [`PrincipalEnricher`]. `None` ⇒ no
    /// enricher is configured, OR the principal's `sub` did not match
    /// any `scim_users` row for `tenant`.
    ///
    /// Cedar policies reference these as `principal.scim.*` once the
    /// authz entity builder maps the field; SCIM groups in particular
    /// are how the RBAC enricher resolves roles (group →
    /// `group_role_mappings` → role → scopes).
    ///
    /// Serialised so session-stored principals (used for replays) keep
    /// their enrichment without a second DB lookup on hydrate.
    #[serde(default)]
    pub scim: Option<ScimPrincipalAttrs>,
    /// Positive "blocked" signal set by an enricher when it
    /// cannot safely resolve the principal. Distinct from
    /// `scim == None`, which means
    /// "no SCIM data found" (legitimate for service accounts).
    /// `Some(reason)` is a fail-CLOSED state — the bearer
    /// middleware rejects the request with 403.
    ///
    /// Today the only producer is the SCIM resolver when it
    /// sees an ambiguous match (a `sub` matches one row's
    /// `external_id` AND a different row's `user_name`). The
    /// reason field is human-readable string (not enum) so
    /// future enrichers can add their own block reasons
    /// without changing the middleware contract, and so
    /// operators can grep audit logs / 403 bodies for the
    /// literal value.
    #[serde(default)]
    pub enrichment_blocked: Option<String>,
    /// RBAC role names the principal holds in
    /// `tenant`, resolved by an optional RBAC enricher (which
    /// composes after the SCIM enricher and reads direct assignments,
    /// plus current durable membership matching `principal.scim.groups`).
    /// Empty when no enricher ran or no roles matched. Cedar
    /// policies see this as `principal.roles` (a set of strings),
    /// so authors can write
    /// `permit when principal.roles.contains("tenant_admin")`.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Resolved credential-profile context and its optional per-principal
    /// server/tool allow-list. Despite the historical name it is not
    /// API-key-only:
    ///
    /// - `Some` for an
    ///   [`AuthMethod::ApiKey`] principal whose backing
    ///   `api_keys` row references a profile. The profile identity remains
    ///   present even when its server/tool allowlists are empty because its
    ///   scopes, TTL, owner, and reason constraints still describe the
    ///   effective credential context.
    /// - Also `Some` for an [`AuthMethod::Oauth`]
    ///   principal whose access-token `aud` is a registered
    ///   per-upstream resource id — the ID-JAG resource binding
    ///   sets `allowed_servers = [the bound upstream]` so a
    ///   resource-scoped token is confined to that one upstream
    ///   (see `BearerValidator`'s `resolve_resource_binding`).
    ///
    /// `None` otherwise (estate-audience OAuth tokens and legacy api_keys
    /// rows without a profile).
    ///
    /// Resolved on the validator hot path so the invocation gate
    /// doesn't have to re-query per call.
    ///
    /// Cedar / the invocation gate / the `tools/list` filters enforce by
    /// refusing dispatch (and hiding discovery) when `ctx.server` /
    /// `ctx.fq_tool` isn't in the respective list. Namespace-scoped built-ins
    /// apply the same restriction to the built-in name; delegated data-plane
    /// facades apply it to every nested resource instead. See
    /// `waygate_mcp::DefaultInvocationService::check_profile_restrictions`
    /// and `waygate_mcp::authz`'s `profile_blocks_server` /
    /// `profile_blocks_tool` predicates.
    #[serde(default)]
    pub api_key_profile_restrictions: Option<ApiKeyProfileRestrictions>,
}

/// The subset of an API-key profile that the
/// invocation gate enforces. Resolved once at validation time
/// and carried on the [`Principal`] so the hot path stays a
/// single in-memory string comparison.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiKeyProfileRestrictions {
    /// `api_key_profiles.id` for audit + diagnostic surfacing.
    pub profile_id: String,
    /// Human-friendly profile name carried so 403 messages can
    /// say "profile `read_only` forbids server X" without a
    /// store round-trip.
    pub profile_name: String,
    /// `Some(non_empty)` ⇒ dispatch refused unless
    /// `ctx.server` is in the list. `Some([])` ⇒ no restriction
    /// (legitimate state — operator may pre-author as a
    /// placeholder). `None` ⇒ the profile didn't restrict
    /// servers (the common case for profiles that constrain minting but not
    /// dispatch).
    pub allowed_servers: Option<Vec<String>>,
    /// Same shape for `<server>.<tool>` fully-qualified names.
    pub allowed_tools: Option<Vec<String>>,
}

/// SCIM attributes resolved for an authenticated principal. Mirrors
/// the subset of `scim_users` columns + joined group memberships that
/// authorization and audit code actually consume. Designed to be
/// cheap to clone (per-request copy into Cedar entities) and safe to
/// serialise into a session cookie.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScimPrincipalAttrs {
    /// UUID of the matching `scim_users` row. Serialised as a string
    /// so this crate doesn't need a `uuid` dep and so the value
    /// round-trips losslessly through JSON.
    pub user_id: String,
    /// `scim_users.user_name`.
    pub user_name: String,
    /// `scim_users.external_id` — the IdP's stable id for the user.
    /// `None` when the provisioner didn't set one (most do).
    #[serde(default)]
    pub external_id: Option<String>,
    /// `scim_users.active`. SCIM defines a "soft delete": active=false
    /// users are retained in the table but should be denied. Surfacing
    /// the flag lets Cedar policies express
    /// `forbid when !principal.scim.active`.
    pub active: bool,
    /// `scim_users.attrs` JSONB pass-through. Opaque to this crate;
    /// Cedar entity builder is free to flatten or ignore it. Defaults
    /// to JSON null so policies that reference a missing key get a
    /// clean Cedar evaluation error rather than a panic.
    #[serde(default = "default_attrs")]
    pub attrs: serde_json::Value,
    /// SCIM group memberships resolved via
    /// `scim_user_groups` → `scim_groups`. Empty vector when the user
    /// belongs to no groups (distinct from "no SCIM row at all", which
    /// surfaces as `Principal.scim = None`).
    #[serde(default)]
    pub groups: Vec<ScimGroupRef>,
}

fn default_attrs() -> serde_json::Value {
    serde_json::Value::Null
}

/// Lightweight reference to a SCIM group. Display name is what policy
/// authors usually want (`principal.scim.groups.contains("admins")`);
/// the UUID is carried so audit can render a stable identifier even
/// after a group is renamed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScimGroupRef {
    pub id: String,
    pub display_name: String,
}

impl Principal {
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }

    pub fn in_group(&self, group: &str) -> bool {
        self.groups.iter().any(|g| g == group)
    }

    /// The SCIM deactivation signal extends beyond Cedar-gated
    /// paths: every bearer-gated surface must consult it.
    ///
    /// Also returns `true` when an enricher
    /// set [`Self::enrichment_blocked`] — a positive fail-closed
    /// signal distinct from "no SCIM data." Without this, an
    /// ambiguous-match path that returned `scim = None` would
    /// silently bypass the deactivation check entirely.
    ///
    /// Returns `false` only when both:
    /// - no enricher blocked the request, AND
    /// - either SCIM enrichment is absent OR the row is active.
    ///
    /// A principal without any SCIM row (`scim == None`,
    /// `enrichment_blocked == None`) is treated as active —
    /// service accounts, dev mode, and pre-SCIM API keys all
    /// keep working.
    ///
    /// `bearer_middleware` and the dashboard session middleware
    /// consult this before forwarding the request, so a SCIM
    /// deactivation OR an enricher-detected ambiguity takes
    /// effect on every gateway surface within one enricher-cache
    /// TTL.
    pub fn scim_blocks_request(&self) -> bool {
        self.enrichment_blocked.is_some() || matches!(self.scim.as_ref(), Some(s) if !s.active)
    }
}

impl std::fmt::Debug for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Principal")
            .field("sub", &self.sub)
            .field("email", &self.email)
            .field("groups", &self.groups)
            .field("issuer", &self.issuer)
            .field("scopes", &self.scopes)
            .field("auth_method", &self.auth_method)
            .field("raw_token", &self.raw_token.as_ref().map(|_| "<redacted>"))
            .field("scim", &self.scim)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Baseline scope for calling any tool the policy set allows unconditionally.
    McpInvoke,
    /// Step-up scope for `high`-risk (administrative) tools: when a `CallTool`
    /// would be denied for lack of it, the client re-authorizes via OAuth
    /// and retries. The IdP owns the authentication method used for that
    /// fresh login. Maps to `mcp:invoke:high`.
    McpInvokeHigh,
    McpRead,
    McpAdmin,
    /// The HITL control-plane *maker* scope. Lets an automated
    /// caller (e.g. Claude over MCP) PROPOSE a control-plane change
    /// (mint key, edit policy, revoke session) as a pending change
    /// request a human must approve — without holding `mcp:admin`.
    /// Propose-only: it can create + poll change requests, never
    /// execute. See `docs/agents/hitl-control-plane.md`.
    McpPropose,
    /// The read-only observability scope. Lets a (possibly unprivileged)
    /// monitoring agent reach the `gateway-observe.*` MCP read plane — audit
    /// queries, usage/cost reports, authorization simulation, config inventory,
    /// and the triage digest — without holding `mcp:admin`. Strictly read-only:
    /// it carries no mutate authority, returns metadata only (no tokens /
    /// ciphertext), and is tenant-scoped from the principal. `mcp:admin`
    /// satisfies it too (operators can read). Safe to delegate to a federated
    /// peer (unlike `mcp:admin` / `scim:write`).
    McpObserve,
    /// Read SCIM resources via
    /// `/scim/v2/Users` GET endpoints. Lower-privilege
    /// than `ScimWrite` so an external observability tool
    /// pulling user lists doesn't get write-by-accident
    /// privileges.
    ScimRead,
    /// Provision SCIM resources (POST / PUT
    /// / DELETE on `/scim/v2/Users`). The identity provider
    /// (Okta, Authentik, EntraID) mints an API key with
    /// this scope and uses it for its outbound SCIM client.
    ScimWrite,
}

impl Scope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Scope::McpInvoke => "mcp:invoke",
            Scope::McpInvokeHigh => "mcp:invoke:high",
            Scope::McpRead => "mcp:read",
            Scope::McpAdmin => "mcp:admin",
            Scope::McpPropose => "mcp:propose",
            Scope::McpObserve => "mcp:observe",
            Scope::ScimRead => "scim:read",
            Scope::ScimWrite => "scim:write",
        }
    }

    /// Every built-in scope the gateway ships, in declaration order.
    ///
    /// The scope registry migration (`0064_scope_registry.sql`) seeds
    /// exactly this set as `source='builtin'`; the `pg_scope_store`
    /// integration test asserts the seeded `builtin` rows equal
    /// `ALL.map(Scope::as_str)`, so adding a variant above without
    /// teaching the migration the new built-in fails CI. The
    /// exhaustive `match` in [`Self::as_str`] forces a new variant to
    /// be named there; this list is the iterable companion the
    /// catalog seeds from.
    pub const ALL: [Scope; 8] = [
        Scope::McpInvoke,
        Scope::McpInvokeHigh,
        Scope::McpRead,
        Scope::McpAdmin,
        Scope::McpPropose,
        Scope::McpObserve,
        Scope::ScimRead,
        Scope::ScimWrite,
    ];
}
