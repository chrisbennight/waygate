//! Typed authorization facts — the Policy Information Point (PIP)
//! output.
//!
//! Today the Cedar gate builds its entities directly from a
//! `Principal` plus an ad-hoc `ToolFacts`. That couples the policy
//! layer to the wire-level principal shape and limits what a policy can
//! reason about (groups, scopes, risk, side-effects, pii — and nothing
//! else). [`Facts`] is the richer, typed model a PIP assembles per
//! call: principal / client / tenant / action / resource attributes,
//! plus optional request-shape and runtime-context attributes that
//! later phases (rate limits, HITL approval, output inspection, step-up
//! on MFA) gate on.
//!
//! This is the **seed** slice: the types exist but nothing produces or
//! consumes them yet. A later slice rewrites the Cedar entity builder
//! to consume `Facts`, and the invocation pipeline's `extract_facts`
//! stage to produce them — dead code by design until then, mirroring
//! how the catalog and policy stores were rolled out.

use std::net::IpAddr;

use time::OffsetDateTime;

use crate::{RiskTier, TenantId};

/// Everything a policy decision can reason about, assembled per call.
#[derive(Debug, Clone, PartialEq)]
pub struct Facts {
    pub principal: PrincipalFacts,
    pub client: ClientFacts,
    pub tenant: TenantFacts,
    pub action: ActionFacts,
    pub resource: ResourceFacts,
    /// Request-shape facts derived from the call arguments. `None` when
    /// the action carries no arguments (discovery) or the producer
    /// didn't extract them.
    pub request: Option<RequestFacts>,
    pub context: RuntimeContextFacts,
}

/// Who is calling. Mirrors the attributes the Cedar `User` entity
/// carries today (sub, email, groups, scopes, auth_method) plus
/// `roles`, populated by the RBAC layer.
#[derive(Debug, Clone, PartialEq)]
pub struct PrincipalFacts {
    pub sub: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub scopes: Vec<String>,
    /// How the principal authenticated, e.g. `"oauth"` / `"api_key"`.
    pub auth_method: String,
    /// Gateway roles resolved for the principal by the RBAC layer;
    /// empty when the principal has no role assignments.
    pub roles: Vec<String>,
    /// SCIM-resolved facts for the principal, when
    /// the gateway is wired with a SCIM enricher AND the principal's
    /// `sub` matched a `scim_users` row. `None` ⇒ no SCIM data
    /// available (either path absent). Cedar policies that gate on
    /// SCIM membership reference `principal.scim.*`; policies that
    /// don't keep evaluating exactly as before.
    pub scim: Option<ScimFacts>,
}

/// SCIM-resolved facts for the principal. Mirror of
/// `waygate_oidc::ScimPrincipalAttrs` but kept here so the policy
/// fact model stays free of OIDC layering. Producers (the cedar.rs
/// `facts_from` bridge) translate from the wire shape into this
/// typed view.
///
/// ## Projection boundary
///
/// This intentionally projects only the typed columns + group
/// names as first-class fields. The principal's raw `attrs` JSONB
/// (custom IdP-emitted fields like `department`, `costCenter`, …)
/// rides opaquely on [`ScimFacts::attrs`] instead — Cedar requires
/// a typed schema for nested records, so flattening every custom
/// key into first-class Cedar attrs would need a per-tenant config
/// or a schema rev; only top-level keys with a clean Cedar type
/// mapping are surfaced (see the `attrs` field). A
/// `permitted_attrs` allowlist is the natural extension if a real
/// policy ever needs finer control.
#[derive(Debug, Clone, PartialEq)]
pub struct ScimFacts {
    pub user_id: String,
    pub user_name: String,
    pub external_id: Option<String>,
    pub active: bool,
    /// SCIM group display names. The numeric ids are dropped at the
    /// facts layer — policies match on names ("admins" /
    /// "finance"), not on database UUIDs.
    pub group_names: Vec<String>,
    /// Raw `scim_users.attrs` JSONB pass-through.
    /// The Cedar entity builder flattens
    /// top-level keys whose JSON type maps cleanly to Cedar
    /// (string, bool, integer, set of strings) into a
    /// `principal.scim_attrs` record attribute. Nested objects and
    /// floats are dropped — Cedar's restricted-expression vocabulary
    /// doesn't model them losslessly. Defaults to JSON null so a
    /// principal whose SCIM row carries no custom attrs surfaces
    /// as an empty record rather than missing-attribute errors.
    pub attrs: serde_json::Value,
}

/// The OAuth client the call came through, when known.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ClientFacts {
    pub client_id: Option<String>,
}

/// The tenant the call is scoped to.
#[derive(Debug, Clone, PartialEq)]
pub struct TenantFacts {
    pub tenant_id: TenantId,
}

/// What is being attempted. `kind` is the neutral action name
/// (`"CallTool"`, `"ListTools"`, `"SearchTools"`, `"ReadResource"`,
/// admin actions, …); `required_scope` is the OAuth scope the action
/// demands, when it maps to one.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionFacts {
    pub kind: String,
    pub required_scope: Option<String>,
}

/// The value [`ResourceFacts::resource_type`] carries for an inference-plane
/// LLM model. The Cedar entity builder renders such a resource as
/// a distinct `Model` entity (rather than `Tool`), so model-specific policies
/// (e.g. a `permit` on a `premium-models` group) target `resource is Model` and
/// the tool step-up (`resource is Tool`) never double-gates a model. Shared so the
/// producer (the invocation pipeline) and the consumer (the Cedar gate) agree
/// on the exact string.
pub const MODEL_RESOURCE_TYPE: &str = "model";

/// The value [`ResourceFacts::resource_type`] carries for a native MCP
/// resource. The Cedar entity builder renders it as a `Resource` entity whose
/// identity and `uri` attribute are the exact upstream URI.
pub const MCP_RESOURCE_TYPE: &str = "mcp_resource";

/// The value [`ResourceFacts::resource_type`] carries for a gateway-served
/// Agent Skill resource.
pub const SKILL_RESOURCE_TYPE: &str = "skill_resource";

/// The resource being acted on — a tool, with its catalog
/// classification. Carries the existing risk / side-effects / pii
/// attributes plus the richer classification fields the governed
/// catalog tracks, which policies can grow into.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceFacts {
    pub server: String,
    pub tool: String,
    pub risk: RiskTier,
    pub side_effects: bool,
    pub pii: bool,
    pub data_classification: Option<String>,
    pub cost_class: Option<String>,
    /// Exact native MCP resource URI for `ReadResource`; absent for servers,
    /// tools, and models.
    pub uri: Option<String>,
    /// External source origin for an Agent Skill catalog. Present only for
    /// skill actions and never inferred from skill frontmatter.
    pub source_origin: Option<String>,
    /// Immutable identity of the external source revision that supplied the skill.
    ///
    /// The field name is retained for storage and policy compatibility.
    pub artifact_digest: Option<String>,
    /// Verified root tree identity declared by the resolved source revision.
    pub source_tree_digest: Option<String>,
    /// Root `SKILL.md` URI of the owning skill revision.
    pub skill_uri: Option<String>,
    /// Digest of the exact skill revision inside that source revision.
    pub revision_digest: Option<String>,
    /// Digest of the exact resource returned by a skill read.
    pub content_digest: Option<String>,
    /// Path of the resource inside the configured skill source boundary.
    pub source_path: Option<String>,
    /// Immutable source-native object identity for the resource.
    pub source_object: Option<String>,
    /// Coarse resource kind, when the upstream/catalog declares one.
    pub resource_type: Option<String>,
    /// The operation the call selected, for a tool that carries many behind
    /// one name.
    ///
    /// This is the value the caller supplied in the tool's discriminator
    /// argument, present whether or not an operator has classified it — a
    /// policy may want to name an operation nobody has reviewed. `risk`,
    /// `side_effects`, and `pii` already reflect the classification that
    /// applied, so a policy gating on those needs nothing from this field;
    /// it exists for a rule that has to name the operation itself.
    ///
    /// `None` for a tool classified by name alone, and for a call that
    /// supplied no discriminator argument or a non-string one.
    pub operation: Option<String>,
}

/// Facts derived from the call *arguments* — what the call would
/// actually do. These let a policy gate on the request shape (e.g.
/// "forbid sending to more than N recipients", "forbid destructive
/// file ops outside an allowlist") without the gate parsing arguments
/// itself. Populated by the PIP from the tool's argument schema; all
/// optional because most are tool-specific.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RequestFacts {
    pub target_domain: Option<String>,
    pub recipient_count: Option<u32>,
    pub destructive: Option<bool>,
    pub file_paths: Vec<String>,
    /// Stable hash of the canonical arguments — lets an approval grant
    /// bind to specific arguments, and lets evidence
    /// correlate retries of the same call.
    pub argument_hash: String,
}

/// Ambient facts about the call's runtime context — not about who or
/// what, but the surrounding conditions a policy may require (a valid
/// approval grant present, MFA in the auth, time of day, source IP).
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeContextFacts {
    pub approval_present: bool,
    pub mfa: bool,
    pub time: OffsetDateTime,
    pub source_ip: Option<IpAddr>,
    /// Which gateway surface originated the call. Cedar policies gate on
    /// `context.channel` to distinguish a direct client call from a
    /// nested call issued by model-generated Code Mode programs.
    pub channel: InvocationChannelFact,
}

/// The gateway surface a call originated from, as a policy fact. Stamped by
/// the invocation pipeline from the request, never from client-supplied
/// data, so a caller cannot masquerade as a different channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InvocationChannelFact {
    /// An ordinary client call (MCP wire, LLM fast-path, admin surfaces).
    #[default]
    Direct,
    /// A nested call issued by a Code Mode program execution.
    CodeMode,
}

impl InvocationChannelFact {
    /// The exact string Cedar policies compare `context.channel` against.
    pub fn as_str(self) -> &'static str {
        match self {
            InvocationChannelFact::Direct => "direct",
            InvocationChannelFact::CodeMode => "codemode",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time check that the model is constructible end-to-end
    // with the expected field types; guards against a later field
    // churn silently breaking a producer.
    #[test]
    fn facts_are_constructible() {
        let f = Facts {
            principal: PrincipalFacts {
                sub: "alice".into(),
                email: Some("a@example.test".into()),
                groups: vec!["admins".into()],
                scopes: vec!["mcp:read".into()],
                auth_method: "oauth".into(),
                roles: vec![],
                scim: None,
            },
            client: ClientFacts {
                client_id: Some("codex".into()),
            },
            tenant: TenantFacts {
                tenant_id: TenantId::default(),
            },
            action: ActionFacts {
                kind: "CallTool".into(),
                required_scope: Some("mcp:invoke:high".into()),
            },
            resource: ResourceFacts {
                server: "example-messages".into(),
                tool: "send".into(),
                risk: RiskTier::High,
                side_effects: true,
                pii: false,
                data_classification: None,
                cost_class: None,
                uri: None,
                source_origin: None,
                artifact_digest: None,
                source_tree_digest: None,
                skill_uri: None,
                revision_digest: None,
                content_digest: None,
                source_path: None,
                source_object: None,
                resource_type: None,
                operation: None,
            },
            request: Some(RequestFacts {
                recipient_count: Some(2),
                argument_hash: "abc".into(),
                ..Default::default()
            }),
            context: RuntimeContextFacts {
                approval_present: false,
                mfa: true,
                time: OffsetDateTime::UNIX_EPOCH,
                source_ip: None,
                channel: InvocationChannelFact::Direct,
            },
        };
        assert_eq!(f.resource.risk, RiskTier::High);
        assert_eq!(f.request.unwrap().recipient_count, Some(2));
    }
}
