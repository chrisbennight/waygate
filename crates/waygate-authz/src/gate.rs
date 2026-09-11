//! Adapter that lets the MCP layer's [`AuthzGate`] delegate to an
//! [`AuthzEngine`]. Lives here (not in `waygate-mcp`) so that `waygate-mcp`
//! doesn't grow a dependency on Cedar.

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;

use waygate_mcp::authz::{
    build_call_facts, AuthzGate, AuthzVerdict, BuiltinAuthz, ProbeVerdict, SkillAccessFacts,
    ToolFacts,
};
use waygate_mcp::protocol::RiskTier;
use waygate_oidc::Principal;
use waygate_telemetry::metrics::{record_authz_decision, record_authz_latency};

use crate::{
    Action as AuthzAction, AuthzEngine, AuthzOutcome, AuthzResult, Decision, ResourceSpec,
    SkillSpec,
};

pub struct CedarGate {
    engine: Arc<dyn AuthzEngine>,
}

impl CedarGate {
    pub fn new(engine: Arc<dyn AuthzEngine>) -> Self {
        Self { engine }
    }

    fn authorize_skill_action(
        &self,
        principal: &Principal,
        action: &AuthzAction,
        facts: &SkillAccessFacts,
    ) -> AuthzVerdict {
        let core_facts = crate::cedar::facts_from(
            principal,
            action,
            &ResourceSpec::Skill(SkillSpec {
                source_origin: facts.source_origin.clone(),
                artifact_digest: facts.artifact_digest.clone(),
                source_tree_digest: Some(facts.source_tree_digest.clone()),
                skill_uri: facts.skill_uri.clone(),
                resource_uri: facts.resource_uri.clone(),
                revision_digest: facts.revision_digest.clone(),
                content_digest: facts.content_digest.clone(),
                source_path: facts.source_path.clone(),
                source_object: facts.source_object.clone(),
            }),
        );
        let started = Instant::now();
        let verdict = self.evaluate_verdict(&core_facts);
        record_authz_latency(started.elapsed().as_secs_f64());
        let decision_label = verdict_label(&verdict);
        record_authz_decision(decision_label, risk_label(core_facts.resource.risk));
        verdict
    }

    /// A built-in call hit a determining forbid. If it is a STEP-UP forbid —
    /// the action carries a `required_scope` the principal lacks, and adding
    /// that scope would let the call proceed — return the `StepUpRequired` hint
    /// instead of a flat `Forbidden`, so the client knows to re-authorize.
    ///
    /// "Would proceed" for a built-in is Cedar `Allow` **or** a clean baseline
    /// deny (empty `policy_ids`): a built-in has no Cedar permit (its floor is
    /// the handler scope, outside Cedar), so the scope-augmented request flips a
    /// step-up forbid to a baseline deny, never to `Allow` — which is exactly
    /// the case the engine's own `Allow`-only step-up inference misses. A *hard*
    /// operator forbid (one that still fires with the scope added) yields a
    /// non-empty-`policy_ids` deny on the re-eval, so it correctly stays
    /// `Forbidden` and is not bypassable by step-up.
    fn builtin_step_up_or_forbid(
        &self,
        core_facts: &waygate_core::Facts,
        denied: AuthzResult,
    ) -> BuiltinAuthz {
        if let Some(scope) = &core_facts.action.required_scope {
            if !core_facts.principal.scopes.iter().any(|s| s == scope) {
                let mut augmented = core_facts.clone();
                augmented.principal.scopes.push(scope.clone());
                if let AuthzOutcome::Decided(second) = self.engine.try_evaluate_facts(&augmented) {
                    let would_proceed = second.decision == Decision::Allow
                        || (second.decision == Decision::Deny && second.policy_ids.is_empty());
                    if would_proceed {
                        return BuiltinAuthz::StepUpRequired {
                            required_scope: scope.clone(),
                            reason: format!(
                                "denied without `{scope}`; re-authorize with the scope to proceed"
                            ),
                            // The first-pass forbid that gated this built-in is
                            // the determinative step-up policy — record it so the
                            // Decision Log can find built-in step-up decisions by
                            // policy id (cloned; the Forbidden branch below still
                            // needs `denied`).
                            policy_ids: denied.policy_ids.clone(),
                        };
                    }
                }
            }
        }
        BuiltinAuthz::Forbidden {
            reason: format!("forbid policies: {}", denied.policy_ids.join(", ")),
            policy_ids: denied.policy_ids,
            reasons: denied.reasons,
        }
    }
}

impl CedarGate {
    /// Map one engine evaluation into the wire verdict. Shared by the
    /// consuming `authorize_tool_call` and the advisory
    /// `probe_tool_call`, so the two can never diverge on mapping.
    fn evaluate_verdict(&self, facts: &waygate_core::Facts) -> AuthzVerdict {
        let result = self.engine.evaluate_facts(facts);
        match result.decision {
            Decision::Allow => AuthzVerdict::Allow {
                // The permits that matched — recorded in the success audit
                // row (the allow-decision twin of the Deny path's policy_ids)
                // so the Decision Log can reverse-lookup allows by policy id.
                policy_ids: result.policy_ids,
            },
            Decision::Deny => AuthzVerdict::Deny {
                reason: if result.policy_ids.is_empty() {
                    "denied by baseline forbid".into()
                } else {
                    format!("forbid policies: {}", result.policy_ids.join(", "))
                },
                policy_ids: result.policy_ids,
                // Surface Cedar's per-policy reason strings
                // so operators + clients can see *why* a call
                // was denied without re-running the gate
                // offline. Cedar already computed them above
                // (StepUpRequired already uses them via
                // `result.reasons.join`) — the Deny arm must
                // not drop them.
                reasons: result.reasons,
            },
            Decision::StepUpRequired => AuthzVerdict::StepUpRequired {
                // Report the EXACT scope the engine added to flip the deny to
                // an allow — `facts.action.required_scope`, the same value
                // `evaluate_facts` pushed onto the principal's scopes for the
                // step-up re-eval. This is the single source of truth: an MCP
                // tool carries `mcp:invoke:high` for a high-risk call. Models are
                // not step-up-gated (model access is a Cedar-permit
                // concern), so a model never sets `required_scope` here. `None`
                // (a low-risk hand-authored step-up) falls back to the base
                // `mcp:invoke`, preserving the prior advisory scope for that case.
                required_scope: facts
                    .action
                    .required_scope
                    .clone()
                    .unwrap_or_else(|| "mcp:invoke".to_owned()),
                reason: result.reasons.join("; "),
                // The step-up forbid ids the engine returns for a StepUpRequired
                // result — the determinative first-pass forbid (e.g.
                // `step-up-delete-dataset`), not the scope-augmented permit —
                // recorded in the step-up audit row so the Decision Log can
                // reverse-lookup step-up decisions by policy id.
                policy_ids: result.policy_ids,
            },
            Decision::ApprovalRequired => AuthzVerdict::ApprovalRequired {
                reason: if result.reasons.is_empty() {
                    "a live per-call approval grant is required".to_owned()
                } else {
                    result.reasons.join("; ")
                },
                // The determinative approval-overlay forbid from the first
                // pass, mirroring the step-up convention, so the Decision Log
                // can reverse-lookup approval-gated decisions by policy id.
                policy_ids: result.policy_ids,
            },
        }
    }
}

/// The metric/tracing label for a mapped verdict — the same vocabulary
/// the engine-decision labels used before the mapping was shared.
fn verdict_label(verdict: &AuthzVerdict) -> &'static str {
    match verdict {
        AuthzVerdict::Allow { .. } => "allow",
        AuthzVerdict::Deny { .. } => "deny",
        AuthzVerdict::StepUpRequired { .. } => "step_up",
        AuthzVerdict::ApprovalRequired { .. } => "approval_required",
    }
}

#[async_trait]
impl AuthzGate for CedarGate {
    async fn may_discover_server(&self, principal: &Principal, server: &str) -> bool {
        let resource = ResourceSpec::Server {
            name: server.to_owned(),
        };
        let result = self
            .engine
            .evaluate(principal, &AuthzAction::SearchTools, &resource);
        result.is_allow()
    }

    async fn may_list_resources(&self, principal: &Principal, server: &str) -> bool {
        self.engine
            .evaluate(
                principal,
                &AuthzAction::ListResources,
                &ResourceSpec::Server {
                    name: server.to_owned(),
                },
            )
            .is_allow()
    }

    #[tracing::instrument(
        skip(self, principal, uri),
        fields(
            server = %server,
            authz.decision = tracing::field::Empty,
        ),
    )]
    async fn authorize_resource_read(
        &self,
        principal: &Principal,
        server: &str,
        uri: &str,
        risk: RiskTier,
    ) -> AuthzVerdict {
        // Built and mapped through the same helper the tool plane uses, so a
        // resource read and a tool call can never disagree about what a Cedar
        // decision means or which policy ids explain it.
        let facts = crate::cedar::facts_from(
            principal,
            &AuthzAction::ReadResource {
                uri: uri.to_owned(),
            },
            &ResourceSpec::McpResource {
                server: server.to_owned(),
                uri: uri.to_owned(),
                risk,
            },
        );
        let started = Instant::now();
        let verdict = self.evaluate_verdict(&facts);
        record_authz_latency(started.elapsed().as_secs_f64());
        let decision_label = verdict_label(&verdict);
        tracing::Span::current().record("authz.decision", decision_label);
        record_authz_decision(decision_label, risk_label(facts.resource.risk));
        verdict
    }

    async fn authorize_skill_list(
        &self,
        principal: &Principal,
        facts: &SkillAccessFacts,
    ) -> AuthzVerdict {
        self.authorize_skill_action(principal, &AuthzAction::ListSkills, facts)
    }

    async fn authorize_skill_fetch(
        &self,
        principal: &Principal,
        facts: &SkillAccessFacts,
    ) -> AuthzVerdict {
        self.authorize_skill_action(
            principal,
            &AuthzAction::FetchSkillResource {
                uri: facts
                    .resource_uri
                    .clone()
                    .unwrap_or_else(|| "skills://catalog".to_owned()),
            },
            facts,
        )
    }

    async fn authorize_skill_read(
        &self,
        principal: &Principal,
        facts: &SkillAccessFacts,
    ) -> AuthzVerdict {
        self.authorize_skill_action(
            principal,
            &AuthzAction::ReadSkill {
                uri: facts
                    .resource_uri
                    .clone()
                    .unwrap_or_else(|| "skills://catalog".to_owned()),
            },
            facts,
        )
    }

    #[tracing::instrument(
        skip(self, facts),
        fields(
            server = %facts.resource.server,
            tool = %facts.resource.tool,
            risk = risk_label(facts.resource.risk),
            authz.decision = tracing::field::Empty,
        ),
    )]
    async fn authorize_tool_call(&self, facts: &waygate_core::Facts) -> AuthzVerdict {
        let started = Instant::now();
        let verdict = self.evaluate_verdict(facts);
        record_authz_latency(started.elapsed().as_secs_f64());
        let decision_label = verdict_label(&verdict);
        tracing::Span::current().record("authz.decision", decision_label);
        record_authz_decision(decision_label, risk_label(facts.resource.risk));
        verdict
    }

    /// Advisory evaluation: records NO authz metrics. The sampling rule
    /// is "whoever terminates the request records its one sample" — a
    /// pass-through is sampled by the pipeline's `authorize_tool_call`,
    /// and the pre-parse gate records the sample itself when its probe
    /// result terminates the request early (a deny, or an allow whose
    /// quota probe then refuses). Recording here instead would
    /// double-sample every pass-through, including a probe deny that a
    /// break-glass claim later converts.
    async fn probe_tool_call(&self, facts: &waygate_core::Facts) -> ProbeVerdict {
        ProbeVerdict::Settled(self.evaluate_verdict(facts))
    }
    /// Forbid-overlay authorization for a built-in tool call.
    ///
    /// Uses the engine's error-preserving [`try_evaluate_facts`] so an
    /// authorization-engine failure becomes [`BuiltinAuthz::Indeterminate`]
    /// (the overlay fails closed) rather than the empty-`policy_ids` baseline
    /// `Deny` the default `evaluate_facts` would synthesize — which the overlay
    /// proceeds on (no-lockout) and would therefore wave the call through on an
    /// engine error. A determining `forbid` → `Forbidden`; a clean baseline
    /// deny → `Proceed` (the scope self-gate is the floor); `Allow` → `Proceed`.
    async fn authorize_builtin_call(
        &self,
        principal: &Principal,
        facts: &ToolFacts,
    ) -> BuiltinAuthz {
        let core_facts = build_call_facts(principal, facts);
        let result = match self.engine.try_evaluate_facts(&core_facts) {
            AuthzOutcome::Decided(r) => r,
            AuthzOutcome::EngineError => {
                // Never surface engine internals to the caller:
                // the operator-facing detail is already logged at the engine.
                return BuiltinAuthz::Indeterminate {
                    reason: "authorization engine could not evaluate the request".into(),
                };
            }
        };
        match result.decision {
            Decision::Allow => BuiltinAuthz::Proceed,
            // Clean baseline deny (no determining forbid) — proceed; the
            // namespace scope self-gate remains the authoritative floor.
            Decision::Deny if result.policy_ids.is_empty() => BuiltinAuthz::Proceed,
            // A determining forbid. Before reporting Forbidden, check whether
            // it is a STEP-UP forbid that the built-in's scope floor would
            // otherwise satisfy. The engine's own step-up inference only emits
            // StepUpRequired when the scope-augmented request becomes Cedar
            // `Allow` — but a built-in has no Cedar permit (its floor is the
            // handler scope, outside Cedar), so adding the scope flips it to a
            // *clean baseline deny* (→ proceed), never to Allow. Without this,
            // an `mcp:admin`-only caller of a High `gateway-control` tool hits
            // the default `30-step-up` forbid and gets a flat Forbidden instead
            // of the actionable `insufficient_scope` hint, even though retrying
            // with `mcp:invoke:high` would proceed.
            Decision::Deny => self.builtin_step_up_or_forbid(&core_facts, result),
            // Built-ins have no grant-claiming dispatch stage, so an
            // approval-overlay gate on a built-in is an authored restriction
            // the overlay cannot satisfy — fail closed as Forbidden rather
            // than proceed past an operator-authored gate.
            Decision::ApprovalRequired => BuiltinAuthz::Forbidden {
                reason: format!(
                    "approval-gated by policies: {}",
                    result.policy_ids.join(", ")
                ),
                policy_ids: result.policy_ids,
                reasons: result.reasons,
            },
            Decision::StepUpRequired => BuiltinAuthz::StepUpRequired {
                required_scope: core_facts
                    .action
                    .required_scope
                    .clone()
                    .unwrap_or_else(|| "mcp:invoke".to_owned()),
                reason: result.reasons.join("; "),
                // The determinative step-up forbid ids (the engine returns the
                // first-pass forbid for a StepUpRequired result) — recorded so
                // the Decision Log can reverse-look-up built-in step-up
                // decisions by policy id.
                policy_ids: result.policy_ids,
            },
        }
    }
}

fn risk_label(risk: RiskTier) -> &'static str {
    match risk {
        RiskTier::Low => "low",
        RiskTier::Medium => "medium",
        RiskTier::High => "high",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use waygate_core::Facts;
    use waygate_oidc::{AuthMethod, Principal};

    use super::*;
    use crate::{AuthzOutcome, AuthzResult, Decision};

    /// Engine that returns a canned outcome from the strict path — lets us
    /// drive `authorize_builtin_call`'s mapping, including the
    /// EngineError → Indeterminate fail-closed branch the production
    /// `CedarEngine` reaches on a build/evaluation error.
    struct FakeEngine(AuthzOutcome);

    impl AuthzEngine for FakeEngine {
        fn evaluate_facts(&self, _facts: &Facts) -> AuthzResult {
            match &self.0 {
                AuthzOutcome::Decided(r) => r.clone(),
                // The non-strict path fails closed to a baseline deny, matching
                // the real CedarEngine's `evaluate_facts`.
                AuthzOutcome::EngineError => AuthzResult {
                    decision: Decision::Deny,
                    reasons: Vec::new(),
                    policy_ids: Vec::new(),
                },
            }
        }
        fn try_evaluate_facts(&self, _facts: &Facts) -> AuthzOutcome {
            self.0.clone()
        }
    }

    fn principal() -> Principal {
        Principal {
            sub: "p".into(),
            email: None,
            groups: vec![],
            issuer: "test".into(),
            scopes: vec!["mcp:admin".into()],
            tenant: waygate_core::TenantId::default(),
            auth_method: AuthMethod::Oauth,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        }
    }

    fn control_facts() -> ToolFacts {
        ToolFacts {
            server: "gateway-control".into(),
            name: "quarantine_server".into(),
            risk: RiskTier::High,
            side_effects: true,
            pii: false,
            requires_approval: false,
            requires_approval_known: true,
        }
    }

    fn gate(outcome: AuthzOutcome) -> CedarGate {
        CedarGate::new(Arc::new(FakeEngine(outcome)))
    }

    // The security core: an engine build/evaluation error MUST NOT look
    // like a proceed-able baseline deny. The strict path surfaces it and
    // the gate maps it to Indeterminate so the overlay fails closed.
    #[tokio::test]
    async fn builtin_call_engine_error_maps_to_indeterminate() {
        let v = gate(AuthzOutcome::EngineError)
            .authorize_builtin_call(&principal(), &control_facts())
            .await;
        assert!(
            matches!(v, BuiltinAuthz::Indeterminate { .. }),
            "engine error must fail closed, got {v:?}"
        );
    }

    #[tokio::test]
    async fn builtin_call_determining_forbid_maps_to_forbidden() {
        let decided = AuthzOutcome::Decided(AuthzResult {
            decision: Decision::Deny,
            reasons: vec!["change-managed".into()],
            policy_ids: vec!["50-gateway-control".into()],
        });
        let v = gate(decided)
            .authorize_builtin_call(&principal(), &control_facts())
            .await;
        assert!(
            matches!(v, BuiltinAuthz::Forbidden { .. }),
            "a determining forbid must map to Forbidden, got {v:?}"
        );
    }

    #[tokio::test]
    async fn builtin_call_clean_baseline_deny_proceeds() {
        // A Decided Deny with EMPTY policy_ids — a clean baseline deny, NOT an
        // engine error — must proceed so the scope floor governs (no lockout).
        let decided = AuthzOutcome::Decided(AuthzResult {
            decision: Decision::Deny,
            reasons: Vec::new(),
            policy_ids: Vec::new(),
        });
        let v = gate(decided)
            .authorize_builtin_call(&principal(), &control_facts())
            .await;
        assert!(
            matches!(v, BuiltinAuthz::Proceed),
            "a clean baseline deny must proceed, got {v:?}"
        );
    }

    #[tokio::test]
    async fn builtin_call_allow_proceeds() {
        let decided = AuthzOutcome::Decided(AuthzResult {
            decision: Decision::Allow,
            reasons: Vec::new(),
            policy_ids: Vec::new(),
        });
        let v = gate(decided)
            .authorize_builtin_call(&principal(), &control_facts())
            .await;
        assert!(matches!(v, BuiltinAuthz::Proceed), "got {v:?}");
    }

    fn real_gate(policy_src: &str) -> CedarGate {
        let engine = crate::CedarEngine::from_source(policy_src).expect("parse policy");
        CedarGate::new(Arc::new(engine))
    }

    // Mirrors the default `crates/waygate-authz/tests/fixtures/policies/30-step-up.cedar`: forbid high-risk Tool
    // calls that lack `mcp:invoke:high`.
    const STEP_UP_POLICY: &str = r#"
        forbid (principal, action == Action::"CallTool", resource is Tool)
        when { resource.risk == "high" && !principal.scopes.contains("mcp:invoke:high") };
    "#;

    // A built-in's floor is the handler scope, not a Cedar permit, so the
    // scope-augmented request flips a step-up forbid to a
    // clean baseline deny (never to Allow) — which the engine's Allow-only
    // step-up inference misses. The gate's built-in step-up detection must still
    // surface the actionable hint instead of a flat Forbidden.
    #[tokio::test]
    async fn builtin_step_up_forbid_yields_hint_for_scope_only_caller() {
        // principal() holds `mcp:admin` (the floor) but NOT `mcp:invoke:high`
        // and is in no group, so there's no Cedar permit — exactly the case.
        let v = real_gate(STEP_UP_POLICY)
            .authorize_builtin_call(&principal(), &control_facts())
            .await;
        match v {
            BuiltinAuthz::StepUpRequired {
                required_scope,
                policy_ids,
                ..
            } => {
                assert_eq!(required_scope, "mcp:invoke:high");
                // The determinative step-up forbid that fired (first-pass) is
                // threaded onto the built-in step-up surface so its audit row
                // can record it for the Decision Log reverse lookup.
                assert!(
                    !policy_ids.is_empty(),
                    "the built-in step-up must carry the fired forbid id; got empty"
                );
            }
            other => panic!("expected StepUpRequired with mcp:invoke:high, got {other:?}"),
        }
    }

    // A *hard* (non-step-up) operator forbid still fires with the scope added,
    // so it must stay Forbidden — step-up cannot bypass it.
    #[tokio::test]
    async fn builtin_hard_forbid_stays_forbidden_not_step_up() {
        const HARD_FORBID: &str = r#"
            forbid (principal, action == Action::"CallTool", resource)
            when { resource.server == "gateway-control" };
        "#;
        let v = real_gate(HARD_FORBID)
            .authorize_builtin_call(&principal(), &control_facts())
            .await;
        assert!(
            matches!(v, BuiltinAuthz::Forbidden { .. }),
            "a hard server-scoped forbid must stay Forbidden, got {v:?}"
        );
    }

    // Contract (the allow-decision twin of the deny path's policy_ids): an
    // Allow decision carrying Cedar's fired permit ids must surface those ids
    // on the `AuthzVerdict::Allow` so the success audit row can record them —
    // and `is_allow()` must still report true. Driven through `FakeEngine` so
    // the mapping is asserted independently of any specific policy text.
    #[tokio::test]
    async fn allow_verdict_carries_fired_permit_ids() {
        let decided = AuthzOutcome::Decided(AuthzResult {
            decision: Decision::Allow,
            reasons: vec![],
            policy_ids: vec!["10-baseline".into(), "20-team-grant".into()],
        });
        let facts = build_call_facts(&principal(), &control_facts());
        let v = gate(decided).authorize_tool_call(&facts).await;
        match v {
            AuthzVerdict::Allow { policy_ids } => {
                assert_eq!(
                    policy_ids,
                    vec!["10-baseline".to_string(), "20-team-grant".to_string()],
                    "the allow verdict must carry the fired permit ids verbatim",
                );
            }
            other => panic!("expected Allow carrying permit ids, got {other:?}"),
        }
        // The struct variant must not regress the `is_allow()` predicate.
        assert!(AuthzVerdict::Allow {
            policy_ids: vec!["10-baseline".into()]
        }
        .is_allow());
    }

    // End-to-end against a real CedarEngine: a named permit that fires on an
    // allowed call must populate `AuthzVerdict::Allow.policy_ids` (Cedar's
    // `diagnostics().reason()`), so the Decision Log can reverse-look-up allow
    // decisions by policy id. `control_facts()` is High-risk with no step-up
    // forbid here, and the permit grants it — so the call is allowed and the
    // contributing policy id is reported.
    #[tokio::test]
    async fn real_engine_allow_reports_nonempty_policy_ids() {
        const PERMIT: &str = r#"
            permit (principal, action == Action::"CallTool", resource);
        "#;
        let facts = build_call_facts(&principal(), &control_facts());
        let v = real_gate(PERMIT).authorize_tool_call(&facts).await;
        match v {
            AuthzVerdict::Allow { policy_ids } => {
                assert!(
                    !policy_ids.is_empty(),
                    "an allowed call must report the permit id(s) that fired, got empty",
                );
            }
            other => panic!("expected Allow with a fired permit id, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn resource_operations_use_their_dedicated_cedar_actions() {
        const LIST_ONLY: &str = r#"
            permit (principal, action == Action::"ListResources", resource);
        "#;
        let gate = real_gate(LIST_ONLY);
        assert!(
            gate.may_list_resources(&principal(), "example-catalog")
                .await
        );
        assert!(!gate
            .authorize_resource_read(
                &principal(),
                "example-catalog",
                "example-catalog://example-guides/design-v1",
                RiskTier::Low,
            )
            .await
            .is_allow());

        const READ_ONLY: &str = r#"
            permit (principal, action == Action::"ReadResource", resource);
        "#;
        let gate = real_gate(READ_ONLY);
        assert!(
            !gate
                .may_list_resources(&principal(), "example-catalog")
                .await
        );
        assert!(gate
            .authorize_resource_read(
                &principal(),
                "example-catalog",
                "example-catalog://example-guides/design-v1",
                RiskTier::Low,
            )
            .await
            .is_allow());

        const ONE_RESOURCE: &str = r#"
            permit (
                principal,
                action == Action::"ReadResource",
                resource is Resource
            ) when {
                resource.uri == "example-catalog://example-guides/design-v1"
            };
        "#;
        let gate = real_gate(ONE_RESOURCE);
        assert!(gate
            .authorize_resource_read(
                &principal(),
                "example-catalog",
                "example-catalog://example-guides/design-v1",
                RiskTier::Low,
            )
            .await
            .is_allow());
        assert!(!gate
            .authorize_resource_read(
                &principal(),
                "example-catalog",
                "example-catalog://example-guides/render-v1",
                RiskTier::Low,
            )
            .await
            .is_allow());
    }

    #[tokio::test]
    async fn skill_actions_are_distinct_and_expose_verified_origin_facts() {
        const POLICY: &str = r#"
            permit (
                principal,
                action == Action::"FetchSkillResource",
                resource is Resource
            ) when {
                resource.source_origin == "git+https://git.example/api/v1/trusted/skills"
                && resource.artifact_digest == "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                && resource.source_tree_digest == "git-sha1:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                && resource.source_path == "plugins/demo/SKILL.md"
                && resource.source_object == "git-sha1:dddddddddddddddddddddddddddddddddddddddd"
            };
            permit (
                principal,
                action in [Action::"ListSkills", Action::"ReadSkill"],
                resource is Resource
            ) when {
                resource.source_origin == "git+https://git.example/api/v1/trusted/skills"
                && resource.artifact_digest == "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                && resource.source_tree_digest == "git-sha1:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                && resource.source_path == "plugins/demo/SKILL.md"
                && resource.source_object == "git-sha1:dddddddddddddddddddddddddddddddddddddddd"
                && resource.content_digest == "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            };
        "#;
        let trusted = SkillAccessFacts {
            source_origin: "git+https://git.example/api/v1/trusted/skills".into(),
            artifact_digest: format!("sha256:{}", "a".repeat(64)),
            source_tree_digest: format!("git-sha1:{}", "e".repeat(40)),
            skill_uri: Some("skill://catalog/demo/SKILL.md".into()),
            resource_uri: Some("skill://catalog/demo/SKILL.md".into()),
            revision_digest: Some(format!("sha256:{}", "b".repeat(64))),
            content_digest: Some(format!("sha256:{}", "c".repeat(64))),
            source_path: Some("plugins/demo/SKILL.md".into()),
            source_object: Some(format!("git-sha1:{}", "d".repeat(40))),
        };
        let gate = real_gate(POLICY);

        assert!(gate
            .authorize_skill_list(&principal(), &trusted)
            .await
            .is_allow());
        let mut fetch = trusted.clone();
        fetch.content_digest = None;
        assert!(gate
            .authorize_skill_fetch(&principal(), &fetch)
            .await
            .is_allow());
        assert!(gate
            .authorize_skill_read(&principal(), &trusted)
            .await
            .is_allow());

        let mut substituted = trusted.clone();
        substituted.source_origin = "git+https://git.example/api/v1/other/skills".into();
        assert!(!gate
            .authorize_skill_read(&principal(), &substituted)
            .await
            .is_allow());

        let resource_only =
            real_gate(r#"permit (principal, action == Action::"ReadResource", resource);"#);
        assert!(!resource_only
            .authorize_skill_read(&principal(), &trusted)
            .await
            .is_allow());
    }

    #[tokio::test]
    async fn declared_resource_risk_can_reach_the_step_up_verdict() {
        const RESOURCE_STEP_UP: &str = r#"
            permit (principal, action == Action::"ReadResource", resource);
            forbid (
                principal,
                action == Action::"ReadResource",
                resource is Resource
            ) when {
                resource.risk == "high"
            } unless {
                principal.scopes.contains("mcp:invoke:high")
            };
        "#;
        let verdict = real_gate(RESOURCE_STEP_UP)
            .authorize_resource_read(
                &principal(),
                "browser",
                "browser://screenshot/handle/capture.png",
                RiskTier::High,
            )
            .await;

        assert!(
            matches!(verdict, AuthzVerdict::StepUpRequired { ref required_scope, .. } if required_scope == "mcp:invoke:high"),
            "high-risk resource should expose a satisfiable step-up: {verdict:?}",
        );
    }
}
