//! Shared domain types for the gateway.
//!
//! `waygate-core` exists to hold types that span multiple crates
//! without forcing them through one of the heavier crates
//! (`waygate-oidc`, `waygate-mcp`). Keeping it dependency-light
//! (no async, no DB, no HTTP) lets any crate depend on it without
//! pulling in a dependency tree.
//!
//! The seed type is `TenantId`. Every other shared type that needs
//! to be tenant-aware lives here so its consumers (catalog,
//! SCIM/RBAC, audit, etc.) can refer to a single source of truth.

mod email_recipients;
pub mod env;
pub use email_recipients::EmailRecipients;
mod facts;
pub mod fmt;
pub mod html;
#[cfg(feature = "http")]
pub mod http_client;
mod invocation;
pub mod net;
pub mod page;
mod risk;
pub mod store;
mod tenant;

pub use facts::{
    ActionFacts, ClientFacts, Facts, InvocationChannelFact, PrincipalFacts, RequestFacts,
    ResourceFacts, RuntimeContextFacts, ScimFacts, TenantFacts, MCP_RESOURCE_TYPE,
    MODEL_RESOURCE_TYPE, SKILL_RESOURCE_TYPE,
};
pub use invocation::InvocationHierarchy;
pub use risk::RiskTier;
pub use tenant::{TenantId, TenantIdError};

/// Scopes that confer authority over the gateway control plane. Membership
/// changes that grant or revoke these scopes use the protected approval bar,
/// and bearer-time RBAC deliberately does not cache resolutions containing
/// them so a committed revocation is observed across replicas on the next
/// request.
pub const CONTROL_PLANE_SCOPES: &[&str] = &["mcp:admin", "mcp:propose", "scim:write"];

/// The primary reserved MCP tool namespace the gateway answers itself (the HITL
/// control-plane built-in tools: `gateway-admin.propose_change`, etc.).
///
/// Lives here, in the dependency-light core, because two otherwise-unrelated
/// crates must agree on it: `waygate-mcp` / `waygate-server` dispatch this
/// prefix to the built-in `BuiltinTools` handler *before* the
/// `<server>.<tool>` upstream split, and `waygate-upstream`'s manifest
/// validation rejects an upstream registered under this name (an upstream so
/// named would be silently shadowed — every call diverted to the built-in
/// tools). One source of truth keeps the dispatch precedence and the load-time
/// guard from drifting apart.
pub const RESERVED_BUILTIN_NAMESPACE: &str = "gateway-admin";

/// Read/analysis built-in namespace (`gateway-observe.*`): the `mcp:observe`
/// read plane (audit queries, usage reports, authorization simulation,
/// config inventory, triage digest).
pub const OBSERVE_BUILTIN_NAMESPACE: &str = "gateway-observe";

/// Direct control built-in namespace (`gateway-control.*`): the `mcp:admin`
/// operational levers (quarantine/reconnect/reload/sweep). Reserved here ahead
/// of its handler so an upstream can never claim the name in the interim.
pub const CONTROL_BUILTIN_NAMESPACE: &str = "gateway-control";

/// File-transfer compatibility tools for clients that do not implement the
/// draft MCP file methods themselves.
pub const FILES_BUILTIN_NAMESPACE: &str = "gateway-files";

/// Gateway-owned external-skill catalog namespace. Cedar decisions, API-key
/// resource profiles, and audit evidence use this identity, so an upstream
/// must never reuse it and make authority or attribution ambiguous.
pub const SKILLS_SERVER_NAMESPACE: &str = "gateway-skills";

/// Audit reason for a skill request refused by the caller's resource profile
/// before Cedar evaluates it. Decision replay treats this as no policy verdict.
pub const SKILL_PROFILE_REFUSAL_REASON: &str =
    "skill access refused by resource profile before policy";

/// Audit reason prefix for a skill request that Cedar allowed but a later
/// origin, validation, or inspection boundary refused. Decision replay treats
/// the recorded policy verdict as allow while preserving the refusal detail.
pub const SKILL_POST_AUTHORIZATION_REFUSAL_PREFIX: &str =
    "skill access refused after policy allowed: ";

/// URI prefix of a file held in this gateway's own storage, as minted by the
/// file plane and accepted back from callers.
///
/// The namespace is self-describing on purpose: a surface that consumes a
/// caller-supplied file reference recognizes one by this prefix and treats
/// nothing else as a file, so a caller cannot smuggle an arbitrary URL into a
/// field the gateway will read. Recognizing the prefix is not authorization —
/// the file plane still resolves the id, checks ownership, and applies
/// credential-profile restrictions before any byte is read.
pub const GATEWAY_FILE_URI_PREFIX: &str = "mcp-file://gateway/";

/// Gateway-native Code Mode data-plane facade (`codemode.*`). The facade
/// delegates discovery to the caller's governed upstream profile and never
/// treats the outer call as nested-call authority.
pub const CODEMODE_BUILTIN_NAMESPACE: &str = "codemode";

/// Gateway-wide governed tool discovery (`gateway-discovery.*`). The facade
/// delegates visibility to the caller's profile and Cedar decisions, then
/// returns catalog records rather than acquiring authority of its own.
pub const DISCOVERY_BUILTIN_NAMESPACE: &str = "gateway-discovery";

/// Every gateway-owned server namespace that an upstream must not reuse.
/// Most entries are built-in tool-dispatch prefixes; others are policy,
/// profile, and audit identities. Manifest validation rejects exact and
/// `<ns>.`-prefixed collisions so authority and attribution stay unambiguous.
pub const RESERVED_BUILTIN_NAMESPACES: &[&str] = &[
    RESERVED_BUILTIN_NAMESPACE,
    OBSERVE_BUILTIN_NAMESPACE,
    CONTROL_BUILTIN_NAMESPACE,
    FILES_BUILTIN_NAMESPACE,
    SKILLS_SERVER_NAMESPACE,
    CODEMODE_BUILTIN_NAMESPACE,
    DISCOVERY_BUILTIN_NAMESPACE,
];

/// The inference plane's reserved model namespace. The OpenAI-compatible `/v1`
/// routes build `(LLM_NAMESPACE, <model>)` invocations, and the LLM model
/// resolver *owns* this namespace whenever the LLM path is active — an unknown
/// or not-yet-discovered model under it is rejected, never routed to MCP. So an
/// MCP upstream named exactly `llm` would only register a dead namespace (its
/// tools rejected as unknown models); `waygate-upstream` rejects it at
/// manifest-load instead. This is an EXACT-match reservation (unlike the
/// `<ns>.`-prefixed built-in namespaces above) because the resolver intercepts
/// only the exact `llm` server, not `llm.*`.
pub const LLM_RESERVED_NAMESPACE: &str = "llm";
