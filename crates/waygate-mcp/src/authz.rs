//! Authorization gate the MCP layer consults before exposing or invoking a
//! tool. The gate is abstract so `waygate-mcp` does not depend on
//! `waygate-authz` / Cedar — the real adapter is wired in `waygate-server`.

use async_trait::async_trait;
use std::sync::Arc;

use waygate_oidc::Principal;

use crate::protocol::RiskTier;

/// Immutable source and content facts used for Agent Skills policy decisions.
#[derive(Debug, Clone)]
pub struct SkillAccessFacts {
    pub source_origin: String,
    pub artifact_digest: String,
    pub source_tree_digest: String,
    pub skill_uri: Option<String>,
    pub resource_uri: Option<String>,
    pub revision_digest: Option<String>,
    pub content_digest: Option<String>,
    pub source_path: Option<String>,
    pub source_object: Option<String>,
}

/// Classification context we hand to the gate when asking about a specific
/// tool call. Populated from the per-server manifest's
/// [`ToolClassification`](waygate_upstream::ToolClassification).
///
/// The `pii` field is the legacy Cedar/audit sensitivity signal. Manifest-mode
/// tools populate it from the operator declaration. Annotation-native tools
/// keep it conservatively true until result-level trust facts have their own
/// Cedar attributes and release enforcement.
#[derive(Debug, Clone)]
pub struct ToolFacts {
    pub server: String,
    pub name: String,
    pub risk: RiskTier,
    pub side_effects: bool,
    pub pii: bool,
    /// When true, dispatch requires a matching live
    /// HITL approval grant (per-call human-in-the-loop). The catalog
    /// populates this from `tool_classifications.requires_approval`
    /// when the per-call path consults a `Live` row; the manifest
    /// fallback path defaults to `false` (manifests don't carry the
    /// flag — operators set it in the catalog admin UI).
    pub requires_approval: bool,
    /// Whether the source that
    /// populated `requires_approval` is trustworthy for HITL
    /// enforcement.
    ///
    /// - `true` everywhere a trustworthy source set the flag:
    ///   catalog `Live` (catalog is authoritative), no-catalog-wired
    ///   manifest path (manifest IS authoritative on that
    ///   deployment), or transitional catalog states
    ///   `PendingApproval` / `NotFound` (intentional — those are
    ///   deliberate states, not failures).
    /// - `false` ONLY when the catalog was wired but `resolve_tool`
    ///   errored, so the manifest-fallback's `false` could be lying
    ///   to us. `check_approval` refuses that admitted snapshot rather
    ///   than trusting the demoted flag or changing authority mid-call.
    ///
    /// Without this signal, a transient catalog DB outage would
    /// silently bypass HITL enforcement for tools the catalog
    /// declares `requires_approval=true`.
    pub requires_approval_known: bool,
}

impl ToolFacts {
    /// Whether the operation fits the invocation service's read-only authority
    /// ceiling. Unknown approval requirements fail closed.
    pub fn admitted_by_read_only_ceiling(&self) -> bool {
        !self.side_effects && self.requires_approval_known && !self.requires_approval
    }
}

/// Outcome of a side-effect-free authorization probe
/// ([`AuthzGate::probe_tool_call`]).
#[derive(Debug, Clone)]
pub enum ProbeVerdict {
    /// The consuming evaluation would produce exactly this verdict, and
    /// reaching it involves no side effects.
    Settled(AuthzVerdict),
    /// A consuming mechanism (a live break-glass token) could change the
    /// settled verdict. An advisory caller must fall through to the
    /// pipeline, which owns the claim, its audit trail, and its metrics.
    ConsumingOverridePossible,
}

#[derive(Debug, Clone)]
pub enum AuthzVerdict {
    /// Cedar policy ids that produced the allow (the permits that matched);
    /// recorded in the success audit row so the Decision Log can find allow
    /// decisions by policy id.
    Allow { policy_ids: Vec<String> },
    Deny {
        reason: String,
        policy_ids: Vec<String>,
        /// "Explain this denial": Cedar's
        /// per-policy human-readable reason strings, surfaced
        /// to the MCP client + admin UI so an operator
        /// debugging a denied call can see *why* without
        /// re-running the gate offline. Cedar already
        /// computes these in `Decision::Deny` / `Decision::
        /// StepUpRequired` evaluations; the Deny branch must
        /// forward them rather than drop them. May be empty
        /// when the deny came from baseline (no matching
        /// forbid).
        reasons: Vec<String>,
    },
    /// Step-up reserved for v2 (MFA-gated high-risk calls). Treated as Deny
    /// by current call sites; kept as a distinct variant so UX code can
    /// surface a prompt rather than a flat forbidden.
    StepUpRequired {
        required_scope: String,
        reason: String,
        /// The step-up FORBID ids that fired in the real (first-pass)
        /// evaluation — the determinative policy that required elevation (e.g.
        /// `step-up-delete-dataset`), NOT the hypothetical scope-augmented permit.
        /// Recorded in the step-up audit row so the Decision Log can find
        /// step-up decisions by policy id. See `CedarEngine::evaluate_facts`.
        policy_ids: Vec<String>,
    },
    /// The call is authorized once a live per-call approval grant covers it:
    /// an approval-overlay forbid (conditioned on
    /// `!context.approval_present`) is the only policy standing between the
    /// call and an allow. The invocation pipeline's approval stage enforces
    /// the grant claim; this verdict never dispatches on its own.
    ApprovalRequired {
        reason: String,
        /// The approval-overlay forbid ids from the real (first-pass)
        /// evaluation — the determinative policy requiring approval.
        policy_ids: Vec<String>,
    },
}

impl AuthzVerdict {
    pub fn is_allow(&self) -> bool {
        matches!(self, AuthzVerdict::Allow { .. })
    }

    /// The policies behind this verdict, whichever variant carried them. Every
    /// variant records them for the same reason — a decision that cannot name
    /// the policy that produced it cannot be explained afterwards — so a caller
    /// that only needs the ids should not have to match on the shape.
    pub fn policy_ids(&self) -> &[String] {
        match self {
            AuthzVerdict::Allow { policy_ids }
            | AuthzVerdict::Deny { policy_ids, .. }
            | AuthzVerdict::StepUpRequired { policy_ids, .. }
            | AuthzVerdict::ApprovalRequired { policy_ids, .. } => policy_ids,
        }
    }

    /// Whether the tool should appear in discovery results (`tools/list` and
    /// `searchTools`). Allow obviously yes; StepUpRequired yes as well so
    /// that clients can surface "call this tool after you re-authorize with
    /// scope X" rather than hiding the tool entirely — otherwise the user
    /// never learns step-up is available. Deny hides the tool.
    pub fn is_discoverable(&self) -> bool {
        matches!(
            self,
            AuthzVerdict::Allow { .. }
                | AuthzVerdict::StepUpRequired { .. }
                // Approval-gated tools stay discoverable for the same reason
                // step-up ones do: the caller can obtain the missing
                // authority (an admin-minted grant) and retry.
                | AuthzVerdict::ApprovalRequired { .. }
        )
    }
}

/// Outcome of authorizing a **built-in** (gateway-local) tool call under the
/// Cedar forbid-overlay. Distinct from [`AuthzVerdict`] because the overlay
/// needs a distinction the upstream tool plane does not: a *clean baseline
/// deny* (no policy governs the built-in → proceed, the namespace scope
/// self-gate is the authoritative floor) versus an *engine error* (fail
/// closed). Through [`AuthzVerdict`] those are byte-identical — both a `Deny`
/// with empty `policy_ids` — so the overlay would otherwise wave a call through
/// on an authorization-engine failure.
#[derive(Debug, Clone)]
pub enum BuiltinAuthz {
    /// Let the call reach the built-in handler. Either Cedar allowed it, or it
    /// denied by clean baseline (no determining `forbid`) — in which case the
    /// scope self-gate inside the handler remains the gate.
    Proceed,
    /// A determining Cedar `forbid` blocks the call.
    Forbidden {
        reason: String,
        policy_ids: Vec<String>,
        reasons: Vec<String>,
    },
    /// A step-up policy gates the call behind a scope.
    StepUpRequired {
        required_scope: String,
        reason: String,
        /// The step-up forbid policy ids that gated the call — the
        /// determinative forbid from the real evaluation (e.g.
        /// `step-up-delete-dataset`). Recorded on the built-in step-up audit row
        /// so the Decision Log's `?policy_id=` reverse lookup finds
        /// gateway-control built-in step-up decisions, matching the normal
        /// tool step-up path. May be empty if the engine reported step-up
        /// without a determining forbid id.
        policy_ids: Vec<String>,
    },
    /// The authorization engine could not decide (build/evaluation error). The
    /// overlay MUST fail closed — never proceed on this.
    Indeterminate { reason: String },
}

#[async_trait]
pub trait AuthzGate: Send + Sync + 'static {
    /// Decide whether `principal` can see `server` in the meta-tool list.
    /// Used for `tools/list` and as the pre-filter for `searchTools`
    /// operations. Deny → server is hidden.
    async fn may_discover_server(&self, principal: &Principal, server: &str) -> bool;

    /// Decide whether `principal` may list resources exposed by `server`.
    ///
    /// The fail-closed default prevents adapters that have not implemented
    /// resource actions from silently treating tool discovery as data access.
    async fn may_list_resources(&self, _principal: &Principal, _server: &str) -> bool {
        false
    }

    /// Decide whether `principal` may read `uri` from `server`.
    ///
    /// Returns the full verdict rather than a boolean because a resource read
    /// is a governed data access, not a visibility test: the decision has to
    /// carry the policy ids that produced it (so it can be explained after the
    /// fact and reverse-looked-up in the Decision Log), and a verdict that is
    /// not a plain allow has to stay distinguishable from a flat refusal. A
    /// caller who could satisfy a step-up needs to learn the scope; collapsing
    /// that into `false` tells them only that they may not proceed.
    ///
    /// The fail-closed default keeps resource reads distinct from both tool
    /// discovery and resource listing.
    async fn authorize_resource_read(
        &self,
        _principal: &Principal,
        _server: &str,
        _uri: &str,
        _risk: RiskTier,
    ) -> AuthzVerdict {
        AuthzVerdict::Deny {
            reason: "resource reads are not authorized by this gate".to_owned(),
            policy_ids: Vec::new(),
            reasons: Vec::new(),
        }
    }

    /// Decide whether a caller may enumerate one immutable Agent Skills
    /// catalog. This is separate from upstream resource listing so a policy
    /// cannot accidentally grant skill discovery through an unrelated action.
    async fn authorize_skill_list(
        &self,
        _principal: &Principal,
        _facts: &SkillAccessFacts,
    ) -> AuthzVerdict {
        AuthzVerdict::Deny {
            reason: "skill listing is not authorized by this gate".to_owned(),
            policy_ids: Vec::new(),
            reasons: Vec::new(),
        }
    }

    /// Decide whether a caller may cause the gateway to fetch one indexed
    /// resource from the configured skill source. The facts contain immutable
    /// Git provenance but no content digest because the bytes do not exist in
    /// the gateway yet.
    async fn authorize_skill_fetch(
        &self,
        _principal: &Principal,
        _facts: &SkillAccessFacts,
    ) -> AuthzVerdict {
        AuthzVerdict::Deny {
            reason: "skill source fetches are not authorized by this gate".to_owned(),
            policy_ids: Vec::new(),
            reasons: Vec::new(),
        }
    }

    /// Decide whether a caller may read one verified Agent Skill resource.
    async fn authorize_skill_read(
        &self,
        _principal: &Principal,
        _facts: &SkillAccessFacts,
    ) -> AuthzVerdict {
        AuthzVerdict::Deny {
            reason: "skill reads are not authorized by this gate".to_owned(),
            policy_ids: Vec::new(),
            reasons: Vec::new(),
        }
    }

    /// Decide whether a tool call is allowed, over the typed
    /// [`Facts`](waygate_core::Facts) the invocation pipeline's PIP
    /// assembles. This is the primary call-authorization
    /// entry point.
    async fn authorize_tool_call(&self, facts: &waygate_core::Facts) -> AuthzVerdict;

    /// Side-effect-free twin of
    /// [`authorize_tool_call`](AuthzGate::authorize_tool_call), for
    /// advisory surfaces — the pre-parse routing-header gate — that must
    /// never consume per-call authority. The returned verdict answers
    /// "what *could* the consuming path decide right now?": a `Deny` from
    /// the probe means the real evaluation would also deny at this
    /// instant; anything else means the caller must fall through to the
    /// pipeline, whose `authorize_tool_call` remains the one evaluation
    /// with authority.
    ///
    /// Provided default: delegate to `authorize_tool_call` — correct for
    /// every pure gate (Cedar, allow-all, test fakes), whose evaluation
    /// has no side effects. A decorator that CONSUMES authority on its
    /// authorize path (break-glass claims a single-use token to convert a
    /// Deny) MUST override this: report [`ProbeVerdict::Settled`] only
    /// for verdicts the consuming path would reach with no side effects,
    /// and [`ProbeVerdict::ConsumingOverridePossible`] whenever a
    /// consuming mechanism could change the settled answer — otherwise an
    /// advisory probe would either burn the authority the real dispatch
    /// needed or act on a verdict the pipeline would not produce.
    async fn probe_tool_call(&self, facts: &waygate_core::Facts) -> ProbeVerdict {
        ProbeVerdict::Settled(self.authorize_tool_call(facts).await)
    }

    /// Decide whether `principal` can invoke a tool given its
    /// classification. Provided default: assemble [`Facts`] from
    /// `(principal, facts)` and delegate to
    /// [`authorize_tool_call`](AuthzGate::authorize_tool_call). The
    /// discovery filter (`tools/list` / `searchTools`) uses this; the
    /// invocation pipeline calls `authorize_tool_call` directly with
    /// the richer `Facts` it already built.
    async fn may_call_tool(&self, principal: &Principal, facts: &ToolFacts) -> AuthzVerdict {
        self.authorize_tool_call(&build_call_facts(principal, facts))
            .await
    }

    /// [`may_call_tool`](AuthzGate::may_call_tool) with an explicit
    /// originating channel, for discovery surfaces that answer on behalf of
    /// a non-direct caller — Code Mode's binding admission evaluates with
    /// the `codemode` channel so a channel-conditioned forbid removes the
    /// tool from its bindings exactly as it would deny the dispatch.
    ///
    /// This is a DISCOVERY question, never a dispatch: wrappers whose
    /// `authorize_tool_call` consumes per-call authority (break-glass) must
    /// override this to delegate to their inner gate, exactly as they do
    /// for `may_call_tool`.
    async fn may_call_tool_on_channel(
        &self,
        principal: &Principal,
        facts: &ToolFacts,
        channel: waygate_core::InvocationChannelFact,
    ) -> AuthzVerdict {
        let mut call_facts = build_call_facts(principal, facts);
        call_facts.context.channel = channel;
        self.authorize_tool_call(&call_facts).await
    }

    /// Authorize a **built-in** tool call under the Cedar forbid-overlay.
    ///
    /// Unlike [`may_call_tool`](AuthzGate::may_call_tool), this MUST be able to
    /// fail closed on an authorization-engine error rather than treat it as a
    /// proceed-able baseline deny. The default impl delegates to `may_call_tool`
    /// and maps its [`AuthzVerdict`] — which is correct for stubs that cannot
    /// error (allow-all / fixed-verdict). The Cedar-backed gate **overrides**
    /// this to consult the engine's error-preserving path and return
    /// [`BuiltinAuthz::Indeterminate`] on a build/evaluation failure, because
    /// that is the only impl that can actually fail.
    async fn authorize_builtin_call(
        &self,
        principal: &Principal,
        facts: &ToolFacts,
    ) -> BuiltinAuthz {
        match self.may_call_tool(principal, facts).await {
            AuthzVerdict::Allow { .. } => BuiltinAuthz::Proceed,
            // Empty policy_ids == a clean baseline deny (no determining forbid):
            // the overlay proceeds and the scope floor governs.
            AuthzVerdict::Deny { policy_ids, .. } if policy_ids.is_empty() => BuiltinAuthz::Proceed,
            AuthzVerdict::Deny {
                reason,
                policy_ids,
                reasons,
            } => BuiltinAuthz::Forbidden {
                reason,
                policy_ids,
                reasons,
            },
            AuthzVerdict::StepUpRequired {
                required_scope,
                reason,
                // Forward the determinative step-up forbid ids onto the
                // built-in step-up surface so its audit row records them and
                // the Decision Log can reverse-look-up built-in step-up
                // decisions by policy id.
                policy_ids,
            } => BuiltinAuthz::StepUpRequired {
                required_scope,
                reason,
                policy_ids,
            },
            // Built-ins have no grant-claiming dispatch stage, so an authored
            // approval gate on a built-in fails closed.
            AuthzVerdict::ApprovalRequired { reason, policy_ids } => BuiltinAuthz::Forbidden {
                reason,
                policy_ids,
                reasons: Vec::new(),
            },
        }
    }
}

/// Assemble the typed [`Facts`](waygate_core::Facts) for a tool call
/// from the principal and the tool's classification — the gateway's
/// Policy Information Point. Shared by the discovery filter (via
/// `may_call_tool`) and the invocation pipeline's `extract_facts`
/// stage, so both authorize over identical facts.
///
/// Request-shape and runtime-context facts (argument hash, MFA, source
/// IP, …) are left at their defaults until the data sources that feed
/// them are wired in later phases.
/// The OAuth scope a tool's risk tier requires for a call to proceed —
/// `None` for low-risk (no step-up). This is the single source of truth for
/// the risk→scope mapping: the invocation pipeline's `build_call_facts`
/// enforces it (step-up), and `searchTools` exposes it on each
/// `OperationDescriptor.scope` and filters discovery by it (SEP #1888's
/// `scope` facet). Keeping one function means the scope a client *sees* and
/// *filters by* is exactly the scope the call will be *gated on*.
pub fn required_scope_for(risk: RiskTier) -> Option<&'static str> {
    match risk {
        // `medium` is retired for authz (no step-up); treated as low. The
        // RiskTier::Medium variant is retained only for the upstream quarantine
        // threshold. See docs/authorization-model.md §4.
        RiskTier::Low | RiskTier::Medium => None,
        RiskTier::High => Some("mcp:invoke:high"),
    }
}

/// Whether a principal's profile restriction hides an entire discovery
/// namespace.
///
/// A populated `allowed_servers` list must contain `server`. A populated
/// `allowed_tools` list also implicitly hides a server when no entry begins
/// with `<server>.`; this prevents a tool-confined principal from enumerating
/// unrelated namespaces.
///
/// This predicate is shared by ordinary MCP discovery and delegated
/// data-plane surfaces. Keeping it here ensures they interpret the profile
/// exactly as direct tool dispatch does.
pub fn profile_blocks_server(principal: &Principal, server: &str) -> bool {
    let Some(restrictions) = principal.api_key_profile_restrictions.as_ref() else {
        return false;
    };
    let blocked_by_server_list = match restrictions.allowed_servers.as_deref() {
        None | Some([]) => false,
        Some(servers) => !servers.iter().any(|candidate| candidate == server),
    };
    if blocked_by_server_list {
        return true;
    }
    let server_prefix = format!("{server}.");
    match restrictions.allowed_tools.as_deref() {
        None | Some([]) => false,
        Some(tools) => !tools
            .iter()
            .any(|candidate| candidate.starts_with(&server_prefix)),
    }
}

/// Whether a principal's profile restriction hides one fully-qualified tool.
pub fn profile_blocks_tool(principal: &Principal, server: &str, tool: &str) -> bool {
    let Some(restrictions) = principal.api_key_profile_restrictions.as_ref() else {
        return false;
    };
    match restrictions.allowed_tools.as_deref() {
        None | Some([]) => false,
        Some(tools) => {
            let fully_qualified = format!("{server}.{tool}");
            !tools.iter().any(|candidate| candidate == &fully_qualified)
        }
    }
}

/// Whether profile confinement blocks native resources on `server`.
///
/// A populated `allowed_tools` list grants exact tools, not every other data
/// surface in the same namespace. Native resources therefore fail closed for
/// tool-confined profiles. Resource-capable profiles use `allowed_servers`
/// without `allowed_tools`, followed by the dedicated resource Cedar actions.
pub fn profile_blocks_resources(principal: &Principal, server: &str) -> bool {
    if profile_blocks_server(principal, server) {
        return true;
    }
    principal
        .api_key_profile_restrictions
        .as_ref()
        .and_then(|restrictions| restrictions.allowed_tools.as_deref())
        .is_some_and(|tools| !tools.is_empty())
}

pub fn build_call_facts(principal: &Principal, facts: &ToolFacts) -> waygate_core::Facts {
    let required_scope = required_scope_for(facts.risk).map(str::to_owned);
    waygate_core::Facts {
        principal: waygate_core::PrincipalFacts {
            sub: principal.sub.clone(),
            email: principal.email.clone(),
            groups: principal.groups.clone(),
            scopes: principal.scopes.clone(),
            auth_method: principal.auth_method.as_str().to_owned(),
            // Bridge RBAC-resolved roles into the
            // policy fact model on the call-path Facts builder.
            roles: principal.roles.clone(),
            // Bridge SCIM-resolved attrs into the
            // policy fact model so call-path policies (`forbid when
            // !principal.scim.active`) see them. None when no SCIM
            // enricher ran for this request.
            scim: principal.scim.as_ref().map(|s| waygate_core::ScimFacts {
                user_id: s.user_id.clone(),
                user_name: s.user_name.clone(),
                external_id: s.external_id.clone(),
                active: s.active,
                group_names: s.groups.iter().map(|g| g.display_name.clone()).collect(),
                attrs: s.attrs.clone(),
            }),
        },
        client: waygate_core::ClientFacts::default(),
        tenant: waygate_core::TenantFacts {
            tenant_id: principal.tenant.clone(),
        },
        action: waygate_core::ActionFacts {
            kind: "CallTool".to_owned(),
            required_scope,
        },
        resource: waygate_core::ResourceFacts {
            server: facts.server.clone(),
            tool: facts.name.clone(),
            risk: facts.risk,
            side_effects: facts.side_effects,
            pii: facts.pii,
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
        request: None,
        context: waygate_core::RuntimeContextFacts {
            approval_present: false,
            mfa: false,
            time: time::OffsetDateTime::UNIX_EPOCH,
            source_ip: None,
            // Direct by default; the invocation pipeline re-stamps the
            // channel from the gateway-side request before authorizing.
            channel: waygate_core::InvocationChannelFact::Direct,
        },
    }
}

pub type SharedAuthz = Arc<dyn AuthzGate>;

/// Open-door gate. Intended only for unit tests and the `disabled` auth
/// mode; do not compile into production images.
pub struct AllowAllGate;

#[async_trait]
impl AuthzGate for AllowAllGate {
    async fn may_discover_server(&self, _p: &Principal, _s: &str) -> bool {
        true
    }
    async fn may_list_resources(&self, _p: &Principal, _s: &str) -> bool {
        true
    }
    async fn authorize_resource_read(
        &self,
        _p: &Principal,
        _s: &str,
        _uri: &str,
        _risk: RiskTier,
    ) -> AuthzVerdict {
        AuthzVerdict::Allow {
            policy_ids: Vec::new(),
        }
    }
    async fn authorize_skill_list(
        &self,
        _p: &Principal,
        _facts: &SkillAccessFacts,
    ) -> AuthzVerdict {
        AuthzVerdict::Allow {
            policy_ids: Vec::new(),
        }
    }
    async fn authorize_skill_fetch(
        &self,
        _p: &Principal,
        _facts: &SkillAccessFacts,
    ) -> AuthzVerdict {
        AuthzVerdict::Allow {
            policy_ids: Vec::new(),
        }
    }
    async fn authorize_skill_read(
        &self,
        _p: &Principal,
        _facts: &SkillAccessFacts,
    ) -> AuthzVerdict {
        AuthzVerdict::Allow {
            policy_ids: Vec::new(),
        }
    }
    async fn authorize_tool_call(&self, _facts: &waygate_core::Facts) -> AuthzVerdict {
        AuthzVerdict::Allow {
            policy_ids: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_profile_lists_do_not_restrict_dispatch() {
        let principal = Principal {
            sub: "profiled-user".into(),
            email: None,
            groups: Vec::new(),
            issuer: "gateway-test".into(),
            scopes: Vec::new(),
            tenant: waygate_core::TenantId::default(),
            auth_method: waygate_oidc::AuthMethod::ApiKey,
            raw_token: None,
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: Some(waygate_oidc::ApiKeyProfileRestrictions {
                profile_id: "minting-only".into(),
                profile_name: "minting-only".into(),
                allowed_servers: Some(Vec::new()),
                allowed_tools: Some(Vec::new()),
            }),
            roles: Vec::new(),
        };

        assert!(!profile_blocks_server(&principal, "documents"));
        assert!(!profile_blocks_tool(&principal, "documents", "upload"));
        assert!(!profile_blocks_resources(&principal, "documents"));
    }

    #[test]
    fn read_only_ceiling_requires_known_non_effectful_non_approval_operation() {
        let mut facts = ToolFacts {
            server: "example".to_owned(),
            name: "read".to_owned(),
            risk: RiskTier::Low,
            side_effects: false,
            pii: false,
            requires_approval: false,
            requires_approval_known: true,
        };
        assert!(facts.admitted_by_read_only_ceiling());

        for (side_effects, requires_approval, requires_approval_known) in [
            (true, false, true),
            (false, true, true),
            (false, false, false),
        ] {
            facts.side_effects = side_effects;
            facts.requires_approval = requires_approval;
            facts.requires_approval_known = requires_approval_known;
            assert!(!facts.admitted_by_read_only_ceiling());
        }
    }
}
