//! Cedar-backed authorization engine.
//!
//! At startup we concatenate every `*.cedar` file in a directory (sorted by
//! filename for deterministic policy ordering) and parse the result as a
//! single [`PolicySet`]. Every request builds fresh entities from the
//! runtime [`Principal`] and the resource being acted on; we do not cache
//! entity material across requests because group membership changes with
//! each token.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision as CedarDecision, Entities, Entity, EntityUid, Policy, PolicyId,
    PolicySet, Request, RestrictedExpression,
};
use regex::Regex;
use thiserror::Error;

use waygate_core::Facts;
use waygate_mcp::protocol::RiskTier;
use waygate_oidc::Principal;

use crate::{Action, AuthzResult, Decision};

#[derive(Debug, Error)]
pub enum CedarError {
    #[error("read policy dir: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse policy set: {0}")]
    Parse(String),
    #[error("invalid entity uid `{uid}`: {err}")]
    Uid { uid: String, err: String },
    #[error("build entities: {0}")]
    Entities(String),
    #[error("build context: {0}")]
    BuildContext(String),
    #[error("build request: {0}")]
    BuildRequest(String),
    /// A Cedar policy errored at request-time evaluation (undefined attribute,
    /// type mismatch) — surfaced via `diagnostics().errors()`. Raised whenever
    /// the dropped policy is a `forbid`, on every path, because Cedar's
    /// skip-on-error would otherwise delete the restriction and let a matching
    /// permit through. Raised on ANY erroring policy on the STRICT path
    /// ([`CedarEngine::evaluate_facts_strict`]). An erroring `permit` on the
    /// lenient path is logged and skipped: it can only remove an allow, which
    /// default-deny already handles.
    #[error("cedar evaluation error: {0}")]
    Eval(String),
    /// Two policies carry the same `@id` annotation. Stable ids MUST be unique
    /// across the whole policy set: a collision would make
    /// `AuthzResult.policy_ids` (and every `audit_log` row) ambiguous and
    /// silently merge two distinct rules in the dashboard and the decision log.
    /// Fail the load loudly instead. Like any load failure it follows the
    /// standard reload isolation: at boot it aborts startup; on SIGHUP
    /// `resolve_policies` first recovers a good bundle from the `policy_bundles`
    /// ledger if it can, and keeps the previous in-memory set only when both
    /// disk and ledger recovery fail (see [`crate::ReloadableCedar`]).
    #[error("duplicate policy @id `{0}` — @id annotations must be unique across all policy files")]
    DuplicateId(String),
}

/// What we're authorizing against. A [`Server`] is used for broad actions
/// like `ListTools`, `SearchTools`, or `ListResources`; a [`Tool`] is used for
/// `CallTool`; and an [`McpResource`] carries the exact URI for
/// `ReadResource`.
#[derive(Debug, Clone)]
pub enum ResourceSpec {
    Server {
        name: String,
    },
    Tool(ToolSpec),
    McpResource {
        server: String,
        uri: String,
        risk: RiskTier,
    },
    Skill(SkillSpec),
}

#[derive(Debug, Clone)]
pub struct SkillSpec {
    pub source_origin: String,
    pub artifact_digest: String,
    pub source_tree_digest: Option<String>,
    pub skill_uri: Option<String>,
    pub resource_uri: Option<String>,
    pub revision_digest: Option<String>,
    pub content_digest: Option<String>,
    pub source_path: Option<String>,
    pub source_object: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ToolSpec {
    pub server: String,
    pub name: String,
    pub risk: RiskTier,
    pub side_effects: bool,
    /// Carried through to the Cedar `Tool` entity as the `pii`
    /// attribute. Sourced from the per-server manifest's
    /// `ToolClassification.pii` flag and threaded through
    /// `waygate_mcp::authz::ToolFacts`. Policies can express PII-aware
    /// rules via `resource.pii == true`.
    pub pii: bool,
    /// The operation the call selected, when the tool carries many behind one
    /// name. Replay reconstructs it from the audit row so a policy branching on
    /// `resource.operation` evaluates the same way it did live; a simulation
    /// that names none produces the entity a name-only tool always did.
    pub operation: Option<String>,
}

pub struct CedarEngine {
    policies: PolicySet,
    authorizer: Authorizer,
}

impl CedarEngine {
    /// Load every `*.cedar` file in `dir` (sorted by filename) and combine
    /// into a single policy set. An empty directory (or one whose files
    /// contain only comments) yields an empty policy set; Cedar's native
    /// deny-by-default semantics then cause every request to be denied.
    pub fn load_dir(dir: &Path) -> Result<Self, CedarError> {
        let mut files: Vec<_> = std::fs::read_dir(dir)?
            .filter_map(|r| r.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .and_then(|s| s.to_str())
                    .map(|s| s.eq_ignore_ascii_case("cedar"))
                    .unwrap_or(false)
            })
            .collect();
        files.sort_by_key(|e| e.file_name());

        let mut combined = String::new();
        for entry in files {
            let src = std::fs::read_to_string(entry.path())?;
            combined.push_str(&src);
            combined.push('\n');
        }
        Self::from_source(&combined)
    }

    pub fn from_source(src: &str) -> Result<Self, CedarError> {
        let parsed = PolicySet::from_str(src).map_err(|e| CedarError::Parse(e.to_string()))?;
        // Re-key policies by their `@id` annotation so identifiers are stable
        // and human-meaningful. Covers BOTH the on-disk loader and the bundle
        // path, since both flow through here.
        let policies = reidentify_from_annotations(&parsed)?;
        Ok(Self {
            policies,
            authorizer: Authorizer::new(),
        })
    }

    /// Snapshot of every policy currently loaded, for the admin API. The
    /// returned `source` is Cedar's canonical re-serialization — useful for
    /// rendering in the dashboard and for diffing against on-disk files.
    pub fn list_policies(&self) -> Vec<PolicySnapshot> {
        self.policies
            .policies()
            .map(|p| PolicySnapshot {
                id: p.id().to_string(),
                effect: match p.effect() {
                    cedar_policy::Effect::Permit => "permit",
                    cedar_policy::Effect::Forbid => "forbid",
                }
                .to_owned(),
                layer: p.annotation("layer").map(str::to_owned),
                description: p.annotation("description").map(str::to_owned),
                tags: p.annotation("tags").map(parse_tags).unwrap_or_default(),
                reason: p.annotation("reason").map(str::to_owned),
                source: p.to_string(),
            })
            .collect()
    }

    /// Every scope literal referenced by the loaded policy set, pulled
    /// from `principal.scopes.contains | containsAny | containsAll(…)`
    /// expressions (anchored on `.scopes.` so a `.groups.contains("…")`
    /// literal isn't misread as a scope).
    ///
    /// The scope-registry reconcile (waygate-server boot + SIGHUP) upserts
    /// these as `source='policy'` so the catalog-only mint check knows
    /// about a scope a policy gates on even when no key or built-in
    /// carries it. Heuristic by design: it reads Cedar's canonical
    /// re-serialization, so a worst case is one extra catalog string,
    /// never a blocked scope.
    pub fn referenced_scopes(&self) -> BTreeSet<String> {
        referenced_scopes_in(self.policies.policies().map(|p| p.to_string()))
    }

    /// Adapter entry point for callers that still hold
    /// `(Principal, Action, ResourceSpec)` (the discovery path). Bridges
    /// to [`Self::evaluate_facts`] via [`facts_from`].
    pub fn evaluate(
        &self,
        principal: &Principal,
        action: &Action,
        resource: &ResourceSpec,
    ) -> Result<AuthzResult, CedarError> {
        self.evaluate_facts(&facts_from(principal, action, resource))
    }

    /// Strict adapter twin of [`Self::evaluate`]: bridges
    /// `(Principal, Action, ResourceSpec)` to [`Self::evaluate_facts_strict`],
    /// so a request-time Cedar evaluation error (a policy referencing an
    /// undefined attribute, a type mismatch) becomes an `Err` instead of being
    /// logged and ignored. The policy-test publish gate uses this so a draft
    /// that is BROKEN at evaluation time (not just parse time) fails its tests
    /// — a lenient `evaluate` would silently evaluate against the degraded
    /// result and could let an assertion pass on a broken draft.
    pub fn evaluate_strict(
        &self,
        principal: &Principal,
        action: &Action,
        resource: &ResourceSpec,
    ) -> Result<AuthzResult, CedarError> {
        self.evaluate_facts_strict(&facts_from(principal, action, resource))
    }

    /// Evaluate a decision over the typed [`Facts`] — the PIP output the
    /// invocation pipeline assembles directly.
    ///
    /// Step-up: on a deny for an action that carries a `required_scope`
    /// (a high-risk `CallTool` or model), re-evaluate with that scope added to
    /// the principal's scopes. If the augmented principal WOULD be
    /// allowed, report `StepUpRequired` and hand the scope back so the
    /// client can re-authorize and retry. Bounded: the re-eval only
    /// runs on a deny path for an action with a `required_scope`, so the
    /// hot allow path still evaluates once.
    ///
    /// Fails with [`CedarError::Eval`] when a `forbid` errored at evaluation:
    /// Cedar skips such a policy, so returning its decision would silently drop
    /// an operator's restriction. An erroring `permit` is skipped and the
    /// decision returned.
    pub fn evaluate_facts(&self, facts: &Facts) -> Result<AuthzResult, CedarError> {
        self.evaluate_facts_inner(facts, false)
    }

    /// Strict variant of [`evaluate_facts`](Self::evaluate_facts): a Cedar
    /// request-time evaluation error (a policy referencing an undefined
    /// attribute, a type mismatch — surfaced via `diagnostics().errors()`)
    /// becomes [`CedarError::Eval`] instead of being logged and ignored.
    ///
    /// The built-in forbid-overlay consumes this through
    /// [`AuthzEngine::try_evaluate_facts`](crate::AuthzEngine::try_evaluate_facts):
    /// an erroring built-in governance policy contributes no `policy_ids`, so
    /// through the lenient path it is indistinguishable from a clean baseline
    /// deny (→ proceed) — which would fail OPEN. The strict path turns it into
    /// an engine error the overlay fails closed on.
    ///
    /// The difference from the lenient path is only the treatment of an erroring
    /// `permit`. Both paths refuse a request whose `forbid` errored; strict also
    /// refuses when the erroring policy was a permit, because a built-in carries
    /// no Cedar permit and so cannot tell a dropped one from "no governance".
    pub fn evaluate_facts_strict(&self, facts: &Facts) -> Result<AuthzResult, CedarError> {
        self.evaluate_facts_inner(facts, true)
    }

    fn evaluate_facts_inner(&self, facts: &Facts, strict: bool) -> Result<AuthzResult, CedarError> {
        let first = self.evaluate_raw_facts(facts, strict)?;
        if first.decision == Decision::Allow {
            return Ok(first);
        }

        if let Some(step_up_scope) = &facts.action.required_scope {
            if !facts.principal.scopes.iter().any(|s| s == step_up_scope) {
                let mut augmented = facts.clone();
                augmented.principal.scopes.push(step_up_scope.clone());
                let second = self.evaluate_raw_facts(&augmented, strict)?;
                if second.decision == Decision::Allow {
                    return Ok(AuthzResult {
                        decision: Decision::StepUpRequired,
                        reasons: vec![format!(
                            "denied without `{step_up_scope}`; re-authorize with the scope to proceed"
                        )],
                        // Record the FIRST-pass forbid that fired in the real
                        // evaluation — the determinative step-up policy (e.g.
                        // `step-up-delete-dataset`) that required elevation — not
                        // the hypothetical scope-augmented permit from `second`.
                        // This is consistent with how a hard Deny records its
                        // fired forbids, and is what lets `audit_log.policy_ids`
                        // (and the `/decisions?policy_id=` reverse lookup) answer
                        // "which decisions matched <step-up policy>". Cheap
                        // clone on the rare step-up path.
                        policy_ids: first.policy_ids.clone(),
                    });
                }
            }
        }

        // Approval inference, mirroring step-up: when a deny would flip to
        // Allow with `context.approval_present`, the only thing blocking the
        // request is an approval-overlay forbid — report ApprovalRequired
        // rather than a flat Deny.
        //
        // Both governed data planes infer it, and each enforces it its own
        // way. A tool call carries the verdict into the invocation pipeline's
        // approval stage, which gates dispatch on a live per-call grant. A
        // resource read has no such stage, so it refuses and names the gate:
        // the caller learns the resource is approval-gated rather than
        // forbidden, and the row records which policy imposed it. Inferring on
        // both is what keeps an approval-gated resource from being reported as
        // an ordinary denial; enforcement staying per-plane is why the
        // widening cannot loosen anything.
        //
        // Two guards keep the inference narrowing-only (approval must
        // remove a forbid, never substitute for a missing permit):
        // - The first pass must have fired a determining forbid. A
        //   baseline deny (no permit anywhere) never infers, so an
        //   unauthorized caller keeps the flat Deny.
        // - No permit determining the flipped Allow may itself reference
        //   `approval_present`. A permit conditioned on the approval
        //   context would let a grant CREATE authorization out of a
        //   baseline deny; the inference refuses (fail closed) and the
        //   caller keeps the flat Deny. Approval semantics belong in
        //   forbids; permits express who is authorized regardless.
        if governs_data_plane(&facts.action.kind)
            && !facts.context.approval_present
            && !first.policy_ids.is_empty()
        {
            let mut approved = facts.clone();
            approved.context.approval_present = true;
            let second = self.evaluate_raw_facts(&approved, strict)?;
            if second.decision == Decision::Allow
                && !self.any_policy_references_approval(&second.policy_ids)
            {
                return Ok(AuthzResult {
                    decision: Decision::ApprovalRequired,
                    reasons: first.reasons.clone(),
                    // First-pass forbid ids: the determinative approval
                    // policy, consistent with the step-up convention above.
                    policy_ids: first.policy_ids.clone(),
                });
            }

            // Stacked gates: the scope-only and approval-only flips each
            // still denied, so try both together. Only a call genuinely
            // gated by BOTH a step-up rule and an approval overlay reaches
            // here — a call the approval flip alone would allow already
            // returned ApprovalRequired above, so this can never invent a
            // step-up requirement Cedar did not declare. StepUpRequired is
            // reported first: after the caller re-authorizes, the ordinary
            // approval inference surfaces the grant requirement.
            if let Some(step_up_scope) = &facts.action.required_scope {
                if !facts.principal.scopes.iter().any(|s| s == step_up_scope) {
                    let mut both = approved;
                    both.principal.scopes.push(step_up_scope.clone());
                    let third = self.evaluate_raw_facts(&both, strict)?;
                    if third.decision == Decision::Allow
                        && !self.any_policy_references_approval(&third.policy_ids)
                    {
                        return Ok(AuthzResult {
                            decision: Decision::StepUpRequired,
                            reasons: vec![format!(
                                "denied without `{step_up_scope}`; re-authorize with the scope to \
                                 proceed"
                            )],
                            policy_ids: first.policy_ids.clone(),
                        });
                    }
                }
            }
        }

        Ok(first)
    }

    /// Whether any of the named policies references `approval_present` in
    /// its AST-rendered text (comments never survive parsing). Used to
    /// refuse approval inference when the flipped Allow was determined by
    /// an approval-conditioned permit — the shape that would let a grant
    /// create authorization instead of narrowing it. An unparsable id or a
    /// spurious string-literal match refuses inference, which fails closed
    /// to the ordinary Deny.
    fn any_policy_references_approval(&self, policy_ids: &[String]) -> bool {
        use std::str::FromStr as _;
        policy_ids.iter().any(|id| {
            cedar_policy::PolicyId::from_str(id)
                .ok()
                .and_then(|pid| self.policies.policy(&pid))
                .is_none_or(|policy| policy.to_string().contains("approval_present"))
        })
    }

    /// Single Cedar pass over [`Facts`] without step-up inference.
    /// Factored out so [`Self::evaluate_facts`] can run the re-eval
    /// cheaply with an augmented (scope-added) copy. When `strict`, a
    /// request-time evaluation error fails the pass with [`CedarError::Eval`]
    /// (see [`Self::evaluate_facts_strict`]).
    fn evaluate_raw_facts(&self, facts: &Facts, strict: bool) -> Result<AuthzResult, CedarError> {
        let (principal_uid, entities) = build_entities(facts)?;
        let action_uid = make_uid("Action", &facts.action.kind)?;
        let resource_uid = resource_uid(facts)?;
        let context = build_context(facts)?;

        let req = Request::new(principal_uid, action_uid, resource_uid, context, None)
            .map_err(|e| CedarError::BuildRequest(e.to_string()))?;

        let resp = self
            .authorizer
            .is_authorized(&req, &self.policies, &entities);
        // Fired-policy IDs in lexical iteration order.
        let policy_ids: Vec<String> = resp
            .diagnostics()
            .reason()
            .map(|id| id.to_string())
            .collect();
        // `reasons` must NOT be sourced from
        // `diagnostics().errors()`, which is Cedar's
        // evaluation-error channel (type mismatches,
        // undefined attrs) — empty for an ordinary forbid.
        // The "explain this denial" UX needs HUMAN-READABLE
        // text. Cedar surfaces this via per-policy
        // `@reason("...")` annotations, looked up on the
        // policy set by the fired policy ID. Policies that
        // don't carry the annotation contribute nothing;
        // empty `reasons` means "the operator hasn't
        // annotated these forbid rules yet" — the
        // `policy_ids` still tell the client WHICH rule
        // fired. Engine evaluation errors stay out of the
        // client-visible surface (logged at warn below).
        let reasons: Vec<String> = resp
            .diagnostics()
            .reason()
            .filter_map(|id| {
                self.policies
                    .policy(id)
                    .and_then(|p| p.annotation("reason"))
                    .map(str::to_owned)
            })
            .collect();
        // Engine evaluation errors → operator log, NOT
        // client-visible. Surfacing them through `reasons`
        // would leak Cedar internals (entity attribute
        // names, policy syntax fragments) to denied callers.
        //
        // Cedar SKIPS a policy whose condition errors: it contributes neither a
        // decision nor a `policy_ids` entry, and evaluation continues with the
        // rest of the set. That is safe for a `permit` — dropping it can only
        // remove an allow, and default-deny catches the request — but it is a
        // fail-OPEN for a `forbid`: the guardrail silently disappears and any
        // matching permit carries the call to Allow. So an erroring forbid is an
        // undecidable request, not a decided one.
        let mut had_eval_error = false;
        let mut restricting_policy_errored = false;
        for err in resp.diagnostics().errors() {
            had_eval_error = true;
            let cedar_policy::AuthorizationError::PolicyEvaluationError(e) = err;
            let id = e.policy_id();
            // An id that resolves to no policy is treated as restricting: we
            // cannot show the dropped rule was permissive, so we must not
            // assume it.
            let restricting = self
                .policies
                .policy(id)
                .is_none_or(|p| p.effect() == cedar_policy::Effect::Forbid);
            if restricting {
                restricting_policy_errored = true;
                tracing::error!(
                    policy_id = %id,
                    error = %err,
                    "cedar forbid policy errored at evaluation; denying the request rather than \
                     dropping the restriction",
                );
            } else {
                // A dropped permit cannot widen access, so the request keeps
                // its decision — blanket deny-on-error would let one broken
                // permit deny traffic the rest of the set still governs.
                tracing::warn!(
                    policy_id = %id,
                    error = %err,
                    "cedar permit policy errored at evaluation; skipping it",
                );
            }
        }
        // STRICT (built-in overlay): ANY erroring policy is fail-closed, not
        // just a forbid. A built-in has no Cedar permit of its own, so a
        // baseline-shaped Deny reads as "no governance → proceed"; an erroring
        // governance policy of either effect is indistinguishable from that and
        // would wave the call through.
        if (strict && had_eval_error) || restricting_policy_errored {
            return Err(CedarError::Eval(
                "policy evaluation error; failing closed".into(),
            ));
        }
        let decision = match resp.decision() {
            CedarDecision::Allow => Decision::Allow,
            CedarDecision::Deny => Decision::Deny,
        };
        Ok(AuthzResult {
            decision,
            reasons,
            policy_ids,
        })
    }
}

/// A single Cedar parse diagnostic mapped to 1-based line/col spans, for an
/// editor's lint gutter. `line`/`col` are 1-based; `col` is
/// counted in Unicode scalar values (Cedar syntax is ASCII, so this matches the
/// editor's column model in practice).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CedarDiagnostic {
    pub line: usize,
    pub col: usize,
    pub end_line: usize,
    pub end_col: usize,
    pub message: String,
}

/// Parse `src` as a Cedar policy set and return parse diagnostics with 1-based
/// line/col spans — empty when it parses cleanly. **Additive**: this does not
/// change [`CedarEngine::from_source`] or [`CedarError::Parse`]; it's a
/// read-only "what's wrong and where" used by the dashboard's as-you-type
/// validator.
///
/// It runs the SAME validation [`CedarEngine::from_source`] does — `PolicySet::
/// from_str` plus the `@id` re-keying that rejects duplicate `@id`s — so the
/// gutter flags exactly the inputs Validate / Save Draft reject as unparseable.
/// (The full publish gate adds further guards — non-empty content, the
/// attached-test gate, impact analysis — that aren't parse-level and so
/// aren't surfaced here.)
///
/// Parse-error spans come from each `ParseError`'s `miette::Diagnostic` labels
/// (byte offsets into `src`); an error with no label is pinned to the start so
/// the gutter still flags it. A duplicate-`@id` collision is pointed at the
/// colliding (second) `@id("…")` occurrence.
pub fn validate_diagnostics(src: &str) -> Vec<CedarDiagnostic> {
    use miette::Diagnostic;
    // 1. Parse errors first (with spans).
    let parsed = match PolicySet::from_str(src) {
        Ok(p) => p,
        Err(errs) => {
            let mut out = Vec::new();
            for err in errs.iter() {
                let message = err.to_string();
                let mut had_label = false;
                if let Some(labels) = Diagnostic::labels(err) {
                    for label in labels {
                        had_label = true;
                        let start = label.offset();
                        let (line, col) = offset_to_line_col(src, start);
                        let (end_line, end_col) = offset_to_line_col(src, start + label.len());
                        let message = match label.label() {
                            Some(l) => format!("{message}: {l}"),
                            None => message.clone(),
                        };
                        out.push(CedarDiagnostic {
                            line,
                            col,
                            end_line,
                            end_col,
                            message,
                        });
                    }
                }
                if !had_label {
                    out.push(CedarDiagnostic {
                        line: 1,
                        col: 1,
                        end_line: 1,
                        end_col: 1,
                        message,
                    });
                }
            }
            return out;
        }
    };
    // 2. The additional rejection `from_source` makes beyond a clean parse:
    //    re-keying by `@id` fails on a duplicate `@id`. Surface it so the gutter
    //    matches what Save/Validate would reject, not just raw parseability.
    if let Err(CedarError::DuplicateId(id)) = reidentify_from_annotations(&parsed) {
        return vec![duplicate_id_diagnostic(src, &id)];
    }
    Vec::new()
}

/// Locate the colliding (second) `@id("<id>")` in `src` and build a diagnostic
/// there; falls back to the start when the literal can't be found (e.g. the id
/// came from the deeper `from_policies` error path rather than an annotation).
fn duplicate_id_diagnostic(src: &str, id: &str) -> CedarDiagnostic {
    let needle = format!("@id(\"{id}\")");
    let mut from = 0usize;
    let mut second = None;
    for n in 0..2 {
        match src[from..].find(&needle) {
            Some(rel) => {
                let at = from + rel;
                from = at + needle.len();
                if n == 1 {
                    second = Some(at);
                }
            }
            None => break,
        }
    }
    let (line, col) = second.map_or((1, 1), |off| offset_to_line_col(src, off));
    CedarDiagnostic {
        line,
        col,
        end_line: line,
        end_col: col + needle.chars().count(),
        message: format!("duplicate @id \"{id}\" — each policy needs a unique @id"),
    }
}

/// 1-based (line, col) for a byte `offset` into `src`, clamped to the source
/// length. `col` counts Unicode scalar values from the line start.
fn offset_to_line_col(src: &str, offset: usize) -> (usize, usize) {
    let target = offset.min(src.len());
    let mut line = 1usize;
    let mut col = 1usize;
    for (i, ch) in src.char_indices() {
        if i >= target {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

/// Whether this action carries actual data to a caller, as opposed to
/// describing the catalog or administering the gateway.
///
/// The approval overlay applies to exactly these: they are the actions where a
/// human might reasonably be asked to sign off before data moves. The context
/// shape and the approval inference must agree on the set — a policy written
/// against `context.approval_present` errors out (and fails closed) on any
/// action the context builder skipped, so a single predicate keeps the two
/// from drifting apart.
fn governs_data_plane(action_kind: &str) -> bool {
    matches!(action_kind, "CallTool" | "ReadResource" | "ReadSkill")
}

/// Scope that, if granted, *might* flip a deny to an allow for this action.
/// `None` when step-up doesn't apply (non-data-plane actions, or Low-risk
/// operations that never need elevation).
fn step_up_scope_for(action: &Action, risk: RiskTier) -> Option<String> {
    match action {
        // Single source of truth for the risk→scope mapping
        // (`waygate_mcp::authz::required_scope_for`): the same scope the
        // discovery path exposes on `OperationDescriptor.scope` and the call
        // path puts in `facts.action.required_scope`. `None` for low-risk.
        Action::CallTool { .. } | Action::ReadResource { .. } | Action::ReadSkill { .. } => {
            waygate_mcp::authz::required_scope_for(risk).map(str::to_owned)
        }
        _ => None,
    }
}

/// Pull every scope literal out of `.scopes.contains|containsAny|containsAll(…)`
/// expressions across `sources` (each a policy's canonical text). Split out as
/// a free fn over an iterator of strings so it's unit-testable without building
/// a real [`PolicySet`].
fn referenced_scopes_in(sources: impl Iterator<Item = String>) -> BTreeSet<String> {
    // Capture the argument list of any `.scopes.contains[/Any/All](…)` call,
    // then pull each `"…"` literal out of it. `[^)]*` is enough: Cedar set
    // literals (`["a","b"]`) carry no inner parens.
    let call = Regex::new(r#"\.scopes\.contains(?:Any|All)?\s*\(([^)]*)\)"#)
        .expect("static scopes-call regex is valid");
    let lit = Regex::new(r#""([^"]*)""#).expect("static string-literal regex is valid");
    let mut out = BTreeSet::new();
    for src in sources {
        for call_cap in call.captures_iter(&src) {
            for lit_cap in lit.captures_iter(&call_cap[1]) {
                let name = &lit_cap[1];
                if !name.is_empty() {
                    out.insert(name.to_owned());
                }
            }
        }
    }
    out
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct PolicySnapshot {
    /// Stable, human-meaningful id from the policy's `@id` annotation
    /// (e.g. `baseline-readonly-tools`). Falls back to Cedar's positional
    /// `policyN` only for un-annotated fragments. This is the id that surfaces
    /// in `AuthzResult.policy_ids`, the simulator, and `audit_log.policy_ids`,
    /// so the dashboard can deep-link a fired policy back to its definition.
    pub id: String,
    pub effect: String,
    /// Evaluation layer from `@layer` — one of `baseline`, `pii-overlay`,
    /// `scim-overlay`, `service-grants`, `step-up-overlay`. Drives the layered
    /// Policies view. `None` for un-annotated fragments.
    #[serde(default)]
    pub layer: Option<String>,
    /// One-line human description from `@description`, if present.
    #[serde(default)]
    pub description: Option<String>,
    /// Free-form tags from `@tags` (comma-separated in source).
    #[serde(default)]
    pub tags: Vec<String>,
    /// Operator-facing explanation from `@reason` — also surfaced to denied
    /// callers when this policy fires. `None` when unannotated.
    #[serde(default)]
    pub reason: Option<String>,
    pub source: String,
}

/// Re-key each static policy by its `@id` annotation so identifiers are STABLE
/// and human-meaningful (`baseline-readonly-tools`) instead of Cedar's
/// positional `policy0..N`. This is the linchpin of the policy UX: the chosen
/// id flows straight into `diagnostics().reason()` → [`AuthzResult::policy_ids`],
/// the simulator, and every `audit_log` row, so the dashboard can deep-link a
/// fired policy to its definition and answer "which decisions matched this
/// policy".
///
/// `PolicySet::from_str` assigns positional ids and treats `@id` as ordinary
/// metadata (Cedar takes no opinion on annotation keys — only its CLI re-keys
/// on `@id`), so the re-key happens here, covering BOTH the on-disk loader and
/// the bundle path (both go through [`CedarEngine::from_source`]).
///
/// A policy with no `@id` keeps its positional id, so un-annotated dev/test
/// fragments and not-yet-migrated bundles still load. A duplicate `@id` is a
/// hard error — a collision would make `policy_ids` ambiguous and silently
/// merge two rules in the UI and audit. `scripts/check-policy-annotations.sh`
/// (fast CI) and the `every_on_disk_policy_has_stable_id_and_layer` test (under
/// `cargo test`) keep the representative fixture set fully and uniquely annotated.
fn reidentify_from_annotations(parsed: &PolicySet) -> Result<PolicySet, CedarError> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut rekeyed: Vec<Policy> = Vec::new();
    for policy in parsed.policies() {
        match policy.annotation("id") {
            Some(id) if !id.is_empty() => {
                if !seen.insert(id.to_owned()) {
                    return Err(CedarError::DuplicateId(id.to_owned()));
                }
                rekeyed.push(policy.new_id(PolicyId::new(id)));
            }
            _ => rekeyed.push(policy.clone()),
        }
    }
    // `from_policies` also rejects a collision between an explicit `@id` and a
    // positional fallback id (e.g. an un-annotated policy whose positional id
    // equals another policy's `@id`). Surface it as our typed error rather than
    // a bare Cedar PolicySetError.
    PolicySet::from_policies(rekeyed).map_err(|e| CedarError::DuplicateId(e.to_string()))
}

/// Split a `@tags("a, b, c")` annotation value into trimmed, non-empty tags.
fn parse_tags(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Build the Cedar entity set from the typed [`Facts`].
///
/// The principal/User entity is sourced from
/// [`PrincipalFacts`](waygate_core::PrincipalFacts) +
/// [`TenantFacts`](waygate_core::TenantFacts); the resource entity from
/// [`ResourceFacts`](waygate_core::ResourceFacts). Calls act on Tool or Model
/// entities, native resource reads act on a Resource entity carrying the exact
/// URI, and broad discovery/list operations act on a Server.
///
/// User gets `email` / `groups` / `scopes` / `auth_method` / `tenant`; Tool
/// gets `server` / `name` / `risk` / `side_effects` / `pii`, plus `operation`
/// on a call that selected one; Resource gets `server` / `uri`; Server gets
/// `name`. (Client / roles / richer resource
/// facts are carried in `Facts` but not yet stamped onto entities — a later
/// slice adds them when policies need them.)
fn build_entities(facts: &Facts) -> Result<(EntityUid, Entities), CedarError> {
    let p = &facts.principal;
    let user_uid = make_uid("User", &p.sub)?;

    let mut entities: Vec<Entity> = Vec::with_capacity(2 + p.groups.len());
    let mut group_parents: HashSet<EntityUid> = HashSet::with_capacity(p.groups.len());

    for g in &p.groups {
        let g_uid = make_uid("Group", g)?;
        group_parents.insert(g_uid.clone());
        entities.push(Entity::with_uid(g_uid));
    }

    let mut user_attrs = HashMap::new();
    if let Some(email) = &p.email {
        user_attrs.insert("email".to_string(), restricted_string(email));
    }
    user_attrs.insert(
        "groups".to_string(),
        RestrictedExpression::new_set(
            p.groups
                .iter()
                .map(|g| RestrictedExpression::new_string(g.clone())),
        ),
    );
    user_attrs.insert(
        "scopes".to_string(),
        RestrictedExpression::new_set(
            p.scopes
                .iter()
                .map(|s| RestrictedExpression::new_string(s.clone())),
        ),
    );
    // How the principal authenticated. Surfaced so policies can write e.g.
    // `principal.auth_method == "oauth"` to forbid API-key callers from a
    // sensitive tool. String, not enum: keeps the Cedar schema human-editable.
    user_attrs.insert("auth_method".to_string(), restricted_string(&p.auth_method));
    // Tenant attribute on the User entity. Policies
    // can write e.g. `principal.tenant == "acme-prod"` to scope
    // a permit. Single-tenant deployments always see
    // `principal.tenant == "default"`; policies that
    // never reference the attribute are unaffected by it.
    user_attrs.insert(
        "tenant".to_string(),
        restricted_string(facts.tenant.tenant_id.as_str()),
    );

    // Exposes RBAC-resolved role names as a Cedar
    // set so policies can write
    // `permit when principal.roles.contains("tenant_admin")`.
    // The RBAC enricher (when wired) populates this after SCIM
    // enrichment; absent enricher leaves it empty, matching the
    // no-RBAC-enricher behaviour.
    user_attrs.insert(
        "roles".to_string(),
        RestrictedExpression::new_set(
            p.roles
                .iter()
                .map(|r| RestrictedExpression::new_string(r.clone())),
        ),
    );

    // Exposes SCIM-resolved attrs as a nested
    // Cedar record so policies can write e.g.
    // `principal.scim_present && principal.scim.active &&
    //  principal.scim.groups.contains("admins")`.
    // The boolean side-channel (`scim_present`) lets a policy
    // distinguish "no SCIM enricher / no row matched" from
    // "row matched but groups is empty," because Cedar can't
    // safely dereference an attribute that isn't on the entity.
    let scim_present = facts.principal.scim.is_some();
    user_attrs.insert(
        "scim_present".to_string(),
        RestrictedExpression::new_bool(scim_present),
    );
    if let Some(scim) = facts.principal.scim.as_ref() {
        // Each scalar lifted to a top-level user attr so policy
        // authors don't have to remember a nested record shape
        // Cedar can't formally type without a schema. Conservative
        // choice; can grow nested record later when a schema lands.
        user_attrs.insert(
            "scim_user_name".to_string(),
            restricted_string(&scim.user_name),
        );
        user_attrs.insert(
            "scim_active".to_string(),
            RestrictedExpression::new_bool(scim.active),
        );
        user_attrs.insert(
            "scim_groups".to_string(),
            RestrictedExpression::new_set(
                scim.group_names
                    .iter()
                    .map(|g| RestrictedExpression::new_string(g.clone())),
            ),
        );
        if let Some(ext) = scim.external_id.as_ref() {
            user_attrs.insert("scim_external_id".to_string(), restricted_string(ext));
        }
        // Flatten the raw SCIM `attrs` JSONB into a Cedar
        // record on the User entity so policies can reference
        // e.g.
        // `principal has scim_attrs && principal.scim_attrs has department
        //  && principal.scim_attrs.department == "engineering"`.
        // Only top-level keys whose JSON type maps cleanly to Cedar
        // (string, bool, integer, set-of-strings) are flattened;
        // nested objects and floats are dropped because Cedar's
        // restricted-expression vocabulary can't model them
        // losslessly. The `has scim_attrs` guard is recommended
        // because a principal without any SCIM custom attrs
        // doesn't get a record (we skip insertion of an empty
        // record to keep entity payloads small).
        if let Some(obj) = scim.attrs.as_object() {
            let mut record: HashMap<String, RestrictedExpression> = HashMap::new();
            for (k, v) in obj {
                if let Some(expr) = json_value_to_restricted(v) {
                    record.insert(k.clone(), expr);
                }
            }
            if !record.is_empty() {
                match RestrictedExpression::new_record(record) {
                    Ok(rec) => {
                        user_attrs.insert("scim_attrs".to_string(), rec);
                    }
                    Err(e) => {
                        // Should be unreachable given the keys we
                        // produce, but never panic in a Cedar
                        // entity build path — log and skip.
                        tracing::warn!(
                            error = %e,
                            "failed to build Cedar record for principal.scim_attrs; skipping",
                        );
                    }
                }
            }
        }
    }

    let user_entity = Entity::new(user_uid.clone(), user_attrs, group_parents)
        .map_err(|e| CedarError::Entities(e.to_string()))?;
    entities.push(user_entity);

    let r = &facts.resource;
    let server_uid = make_uid("Server", &r.server)?;
    let mut server_attrs = HashMap::new();
    server_attrs.insert("name".to_string(), restricted_string(&r.server));
    let server_entity = Entity::new(server_uid.clone(), server_attrs, HashSet::new())
        .map_err(|e| CedarError::Entities(e.to_string()))?;
    entities.push(server_entity);

    if resource_is_mcp_resource(facts) || resource_is_skill(facts) {
        let uri = r
            .uri
            .as_ref()
            .ok_or_else(|| CedarError::Entities("resource facts are missing the URI".into()))?;
        let resource_uid = make_uid("Resource", uri)?;
        let mut attrs = HashMap::new();
        attrs.insert("server".to_string(), restricted_string(&r.server));
        attrs.insert("uri".to_string(), restricted_string(uri));
        attrs.insert("risk".to_string(), restricted_string(r.risk.as_str()));
        if resource_is_skill(facts) {
            for (name, value) in [
                ("source_origin", r.source_origin.as_deref()),
                ("artifact_digest", r.artifact_digest.as_deref()),
                ("source_tree_digest", r.source_tree_digest.as_deref()),
                ("skill_uri", r.skill_uri.as_deref()),
                ("revision_digest", r.revision_digest.as_deref()),
                ("content_digest", r.content_digest.as_deref()),
                ("source_path", r.source_path.as_deref()),
                ("source_object", r.source_object.as_deref()),
            ] {
                if let Some(value) = value {
                    attrs.insert(name.to_owned(), restricted_string(value));
                }
            }
        }
        let resource_entity = Entity::new(resource_uid, attrs, HashSet::from([server_uid]))
            .map_err(|e| CedarError::Entities(e.to_string()))?;
        entities.push(resource_entity);
    } else if resource_is_tool(facts) {
        // An inference-plane model is a distinct `Model` entity type (Phase
        // 3.2) so policies can target `resource is Model` independently of
        // `resource is Tool` — the tool step-up never double-gates a model, and
        // any model-specific policy (e.g. a permit on a group) targets only
        // models. Same
        // attribute surface (server / name / risk / side_effects / pii) so the
        // shared permits (`resource.risk == "low"`, admin-all) apply uniformly.
        let resource_id = format!("{}.{}", r.server, r.tool);
        let entity_type = if resource_is_model(facts) {
            "Model"
        } else {
            "Tool"
        };
        let resource_uid = make_uid(entity_type, &resource_id)?;
        let mut attrs = HashMap::new();
        attrs.insert("server".to_string(), restricted_string(&r.server));
        attrs.insert("name".to_string(), restricted_string(&r.tool));
        attrs.insert("risk".to_string(), restricted_string(r.risk.as_str()));
        attrs.insert(
            "side_effects".to_string(),
            RestrictedExpression::new_bool(r.side_effects),
        );
        attrs.insert("pii".to_string(), RestrictedExpression::new_bool(r.pii));
        // Only present when the call selected one. A policy naming
        // `resource.operation` must guard with `has`, which is also what keeps
        // every existing policy — written before any tool carried operations —
        // evaluating exactly as it did.
        if let Some(operation) = r.operation.as_deref() {
            attrs.insert("operation".to_string(), restricted_string(operation));
        }
        let resource_entity = Entity::new(resource_uid, attrs, HashSet::from([server_uid]))
            .map_err(|e| CedarError::Entities(e.to_string()))?;
        entities.push(resource_entity);
    }

    let built =
        Entities::from_entities(entities, None).map_err(|e| CedarError::Entities(e.to_string()))?;
    Ok((user_uid, built))
}

/// Whether the resource being acted on is a tool (vs a bare server).
/// `CallTool` is the only action that reaches the gate with a tool
/// resource; discovery actions act on a server.
fn resource_is_tool(facts: &Facts) -> bool {
    facts.action.kind == "CallTool"
}

/// Whether the `CallTool` resource is an inference-plane model, which
/// the entity builder renders as a `Model` entity rather than `Tool`.
/// The producer (the invocation pipeline's LLM path) marks it by setting
/// [`waygate_core::MODEL_RESOURCE_TYPE`] on the resource facts.
fn resource_is_model(facts: &Facts) -> bool {
    facts.resource.resource_type.as_deref() == Some(waygate_core::MODEL_RESOURCE_TYPE)
}

fn resource_is_mcp_resource(facts: &Facts) -> bool {
    facts.resource.resource_type.as_deref() == Some(waygate_core::MCP_RESOURCE_TYPE)
}

fn resource_is_skill(facts: &Facts) -> bool {
    facts.resource.resource_type.as_deref() == Some(waygate_core::SKILL_RESOURCE_TYPE)
}

/// Bridge `(Principal, Action, ResourceSpec)` inputs into the typed
/// [`Facts`] the engine evaluates over. Used by the discovery path
/// ([`CedarEngine::evaluate`]) and by the gate's `may_call_tool`
/// compatibility shim; the invocation pipeline instead
/// builds `Facts` itself and calls `evaluate_facts` directly. Fields the
/// entity builder doesn't read yet (client, request, most of context)
/// get placeholder values.
pub(crate) fn facts_from(principal: &Principal, action: &Action, resource: &ResourceSpec) -> Facts {
    let (
        server,
        tool,
        risk,
        side_effects,
        pii,
        uri,
        resource_type,
        source_origin,
        artifact_digest,
        source_tree_digest,
        skill_uri,
        revision_digest,
        content_digest,
        source_path,
        source_object,
    ) = match resource {
        ResourceSpec::Server { name } => (
            name.clone(),
            String::new(),
            RiskTier::Low,
            false,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        ResourceSpec::Tool(t) => (
            t.server.clone(),
            t.name.clone(),
            t.risk,
            t.side_effects,
            t.pii,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        ResourceSpec::McpResource { server, uri, risk } => (
            server.clone(),
            String::new(),
            *risk,
            false,
            false,
            Some(uri.clone()),
            Some(waygate_core::MCP_RESOURCE_TYPE.to_owned()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        ResourceSpec::Skill(skill) => (
            "gateway-skills".to_owned(),
            String::new(),
            RiskTier::Low,
            false,
            false,
            Some(
                skill
                    .resource_uri
                    .clone()
                    .unwrap_or_else(|| "skills://catalog".to_owned()),
            ),
            Some(waygate_core::SKILL_RESOURCE_TYPE.to_owned()),
            Some(skill.source_origin.clone()),
            Some(skill.artifact_digest.clone()),
            skill.source_tree_digest.clone(),
            skill.skill_uri.clone(),
            skill.revision_digest.clone(),
            skill.content_digest.clone(),
            skill.source_path.clone(),
            skill.source_object.clone(),
        ),
    };
    Facts {
        principal: waygate_core::PrincipalFacts {
            sub: principal.sub.clone(),
            email: principal.email.clone(),
            groups: principal.groups.clone(),
            scopes: principal.scopes.clone(),
            auth_method: principal.auth_method.as_str().to_owned(),
            // Bridges RBAC-resolved roles into the
            // policy fact model. The RBAC enricher (when wired)
            // populates `principal.roles` after SCIM enrichment.
            roles: principal.roles.clone(),
            // Bridges SCIM-resolved attrs from the
            // wire principal into the policy fact model. None
            // when no enricher ran or no SCIM row matched.
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
            kind: action_kind(action).to_owned(),
            required_scope: step_up_scope_for(action, risk),
        },
        resource: waygate_core::ResourceFacts {
            server,
            tool,
            risk,
            side_effects,
            pii,
            data_classification: None,
            cost_class: None,
            uri,
            source_origin,
            artifact_digest,
            source_tree_digest,
            skill_uri,
            revision_digest,
            content_digest,
            source_path,
            source_object,
            resource_type,
            operation: match resource {
                ResourceSpec::Tool(t) => t.operation.clone(),
                _ => None,
            },
        },
        request: None,
        // Discovery-path bridge: adapter callers are direct-channel with no
        // grant in hand. mfa / time / source_ip remain placeholders until a
        // producer supplies them; the entity builder doesn't read those.
        context: waygate_core::RuntimeContextFacts {
            approval_present: false,
            mfa: false,
            time: time::OffsetDateTime::UNIX_EPOCH,
            source_ip: None,
            channel: waygate_core::InvocationChannelFact::Direct,
        },
    }
}

/// Public bridge for admin evaluation surfaces (the live simulator, policy
/// tests, bundle preview, and decision-impact replay): the exact [`Facts`]
/// the adapter path evaluates for `(principal, action, resource)`, returned
/// so the caller can stamp runtime context (channel, approval presence)
/// before a facts-level evaluation. Keeping this the same builder the
/// engine's own adapter uses means a simulation can never drift from the
/// live gate's fact model.
pub fn simulation_facts(principal: &Principal, action: &Action, resource: &ResourceSpec) -> Facts {
    facts_from(principal, action, resource)
}

/// Assemble [`Facts`] for an EMA `GrantCrossAppAccess` decision: the
/// `principal` requesting an ID-JAG for `server` (the MCP resource being
/// granted), acting through `client_id` (surfaced to policy as
/// `context.client_id`). Public so the AS token-exchange endpoint's
/// policy adapter (in `waygate-server`) can build the decision without
/// re-implementing the fact model or reaching into `facts_from`.
pub fn cross_app_facts(principal: &Principal, client_id: &str, server: &str) -> Facts {
    let mut facts = facts_from(
        principal,
        &Action::GrantCrossAppAccess,
        &ResourceSpec::Server {
            name: server.to_owned(),
        },
    );
    facts.client.client_id = Some(client_id.to_owned());
    facts
}

/// Neutral action-kind label, shared by the action UID and `Facts`.
fn action_kind(action: &Action) -> &'static str {
    match action {
        Action::ListTools => "ListTools",
        Action::SearchTools => "SearchTools",
        Action::CallTool { .. } => "CallTool",
        Action::ListResources => "ListResources",
        Action::ReadResource { .. } => "ReadResource",
        Action::ListSkills => "ListSkills",
        Action::FetchSkillResource { .. } => "FetchSkillResource",
        Action::ReadSkill { .. } => "ReadSkill",
        Action::AdminManagePolicies => "AdminManagePolicies",
        Action::AdminManageServers => "AdminManageServers",
        Action::AdminViewTelemetry => "AdminViewTelemetry",
        Action::GrantCrossAppAccess => "GrantCrossAppAccess",
    }
}

fn resource_uid(facts: &Facts) -> Result<EntityUid, CedarError> {
    let r = &facts.resource;
    if resource_is_mcp_resource(facts) || resource_is_skill(facts) {
        let uri = r
            .uri
            .as_ref()
            .ok_or_else(|| CedarError::Entities("resource facts are missing the URI".into()))?;
        make_uid("Resource", uri)
    } else if resource_is_tool(facts) {
        let ty = if resource_is_model(facts) {
            "Model"
        } else {
            "Tool"
        };
        make_uid(ty, &format!("{}.{}", r.server, r.tool))
    } else {
        make_uid("Server", &r.server)
    }
}

/// Build the Cedar request [`Context`] from runtime facts. Surfaces the
/// requesting OAuth `client_id` (when present) as `context.client_id`,
/// so policies — notably the EMA `GrantCrossAppAccess` grant in
/// `40-cross-app-access.cedar` — can gate on which client is acting (the
/// "is Engineering allowed to use this model against the observability service"
/// dimension).
///
/// Additive: every pre-EMA path leaves `ClientFacts.client_id` as
/// `None`, yielding an empty context that unchanged policies ignore — so
/// existing tool-plane evaluations are byte-identical.
fn build_context(facts: &Facts) -> Result<Context, CedarError> {
    let mut pairs: Vec<(String, RestrictedExpression)> = Vec::new();
    if let Some(client_id) = facts.client.client_id.as_ref() {
        pairs.push((
            "client_id".to_string(),
            RestrictedExpression::new_string(client_id.clone()),
        ));
    }
    // Every tool call sees the originating channel, so channel-scoped
    // approval-overlay policies (`forbid … when { context.channel ==
    // "codemode" && !context.approval_present }`) evaluate without
    // missing-attribute errors on any channel.
    //
    // A resource read deliberately does NOT get `channel`, even though it
    // shares the approval overlay below. The read path does not carry the
    // originating channel into its facts, so the value here would always read
    // as direct — including for a Code Mode connector recovery that is not.
    // Publishing an attribute the gateway cannot populate truthfully would let
    // an operator write a channel-scoped resource rule that silently never
    // fires, which is worse than the rule being unwritable. Restoring it means
    // threading the channel through the resource authorization first.
    if facts.action.kind == "CallTool" {
        pairs.push((
            "channel".to_string(),
            RestrictedExpression::new_string(facts.context.channel.as_str().to_owned()),
        ));
    }
    // Both governed data planes see whether a live approval grant covers the
    // request, so an approval overlay can gate either one.
    if governs_data_plane(&facts.action.kind) {
        pairs.push((
            "approval_present".to_string(),
            RestrictedExpression::new_bool(facts.context.approval_present),
        ));
    }
    if pairs.is_empty() {
        return Ok(Context::empty());
    }
    Context::from_pairs(pairs).map_err(|e| CedarError::BuildContext(e.to_string()))
}

fn make_uid(ty: &str, id: &str) -> Result<EntityUid, CedarError> {
    let quoted = id.replace('\\', r"\\").replace('"', r#"\""#);
    let raw = format!(r#"{ty}::"{quoted}""#);
    EntityUid::from_str(&raw).map_err(|e| CedarError::Uid {
        uid: raw,
        err: e.to_string(),
    })
}

fn restricted_string(s: &str) -> RestrictedExpression {
    RestrictedExpression::new_string(s.to_string())
}

/// Best-effort JSON → Cedar restricted-expression conversion for the
/// `principal.scim_attrs` flattening path. Returns `None` for shapes
/// Cedar can't model losslessly (nested objects, floats, mixed-type
/// arrays); the caller silently skips those keys so policies
/// referencing them will see a missing-attribute error (which
/// Cedar's `has` guard is the right way to handle).
fn json_value_to_restricted(v: &serde_json::Value) -> Option<RestrictedExpression> {
    match v {
        serde_json::Value::String(s) => Some(RestrictedExpression::new_string(s.clone())),
        serde_json::Value::Bool(b) => Some(RestrictedExpression::new_bool(*b)),
        // Cedar's long is i64; serde_json's `as_i64` returns None
        // for floats / >i64::MAX, which we silently drop. Policies
        // that need floats can be revisited when a real one lands.
        serde_json::Value::Number(n) => n.as_i64().map(RestrictedExpression::new_long),
        serde_json::Value::Array(items) => {
            // Only string arrays — that's how SCIM extension attrs
            // typically express enumerated values
            // (`emails[*].value`, `phoneNumbers[*].value`). Mixed-
            // type arrays don't fit Cedar's typed set; skip.
            let strs: Option<Vec<RestrictedExpression>> = items
                .iter()
                .map(|i| match i {
                    serde_json::Value::String(s) => {
                        Some(RestrictedExpression::new_string(s.clone()))
                    }
                    _ => None,
                })
                .collect();
            strs.map(RestrictedExpression::new_set)
        }
        // Nested objects, null → skip. Nested record support
        // requires a typed schema that this PR doesn't introduce.
        serde_json::Value::Object(_) | serde_json::Value::Null => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ReloadableCedar;

    #[test]
    fn referenced_scopes_extracts_scope_literals_not_group_literals() {
        let sources = vec![
            // contains("X")
            r#"forbid(principal, action, resource) when { resource.name == "delete_dataset" && !principal.scopes.contains("mcp:invoke:high") };"#.to_string(),
            // containsAny([...]) with a custom scope
            r#"permit(principal, action, resource) when { principal.scopes.containsAny(["mcp:read", "custom:thing"]) };"#.to_string(),
            // a groups literal must NOT be picked up
            r#"permit(principal, action, resource) unless { principal.groups.contains("mcp-admins") };"#.to_string(),
        ];
        let got = referenced_scopes_in(sources.into_iter());
        assert!(got.contains("mcp:invoke:high"));
        assert!(got.contains("mcp:read"));
        assert!(got.contains("custom:thing"));
        assert!(
            !got.contains("mcp-admins"),
            "a .groups.contains literal must not be read as a scope",
        );
    }

    #[test]
    fn referenced_scopes_in_is_empty_for_no_scope_calls() {
        let sources = vec![r#"permit(principal, action, resource);"#.to_string()];
        assert!(referenced_scopes_in(sources.into_iter()).is_empty());
    }

    fn alice(groups: &[&str]) -> Principal {
        Principal {
            sub: "alice".into(),
            email: Some("alice@example.com".into()),
            groups: groups.iter().map(|s| (*s).to_string()).collect(),
            issuer: "https://idp.example".into(),
            scopes: vec!["mcp:invoke".into()],
            tenant: waygate_core::TenantId::default(),
            auth_method: waygate_oidc::AuthMethod::Oauth,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        }
    }

    fn api_key_alice(groups: &[&str]) -> Principal {
        Principal {
            auth_method: waygate_oidc::AuthMethod::ApiKey,
            ..alice(groups)
        }
    }

    fn low_tool() -> ResourceSpec {
        ResourceSpec::Tool(ToolSpec {
            operation: None,
            server: "example-messages".into(),
            name: "list_contacts".into(),
            risk: RiskTier::Low,
            side_effects: false,
            pii: false,
        })
    }

    fn high_tool() -> ResourceSpec {
        ResourceSpec::Tool(ToolSpec {
            operation: None,
            server: "example-messages".into(),
            name: "send_msg".into(),
            risk: RiskTier::High,
            side_effects: true,
            pii: false,
        })
    }

    fn pii_tool() -> ResourceSpec {
        ResourceSpec::Tool(ToolSpec {
            operation: None,
            server: "example-messages".into(),
            name: "read_messages".into(),
            risk: RiskTier::Low,
            side_effects: false,
            pii: true,
        })
    }

    /// A built-in control-plane tool — `server` is the reserved
    /// `gateway-control` namespace. The forbid-overlay authorizes
    /// built-in calls over exactly this shape; these tests pin that the real
    /// engine produces the `policy_ids` the overlay's discriminator relies on.
    fn control_tool() -> ResourceSpec {
        ResourceSpec::Tool(ToolSpec {
            operation: None,
            server: "gateway-control".into(),
            name: "quarantine_server".into(),
            risk: RiskTier::High,
            side_effects: true,
            pii: false,
        })
    }

    const ADMIN_POLICY: &str = r#"
        permit (principal in Group::"mcp-admins", action, resource);
        permit (principal, action == Action::"SearchTools", resource);
        permit (
            principal,
            action == Action::"CallTool",
            resource
        ) when { resource.risk == "low" };
    "#;

    #[test]
    fn empty_policy_denies() {
        let eng = CedarEngine::from_source("").expect("empty ok");
        let r = eng
            .evaluate(&alice(&[]), &Action::SearchTools, &low_tool())
            .expect("eval");
        assert_eq!(r.decision, Decision::Deny);
    }

    #[test]
    fn admin_can_call_high_risk() {
        let eng = CedarEngine::from_source(ADMIN_POLICY).expect("parse");
        let r = eng
            .evaluate(
                &alice(&["mcp-admins"]),
                &Action::CallTool {
                    name: "example-messages.messages.send".into(),
                    risk: RiskTier::High,
                },
                &high_tool(),
            )
            .expect("eval");
        assert_eq!(r.decision, Decision::Allow);
    }

    #[test]
    fn non_admin_denied_on_high_risk() {
        let eng = CedarEngine::from_source(ADMIN_POLICY).expect("parse");
        let r = eng
            .evaluate(
                &alice(&["mcp-users"]),
                &Action::CallTool {
                    name: "example-messages.messages.send".into(),
                    risk: RiskTier::High,
                },
                &high_tool(),
            )
            .expect("eval");
        assert_eq!(r.decision, Decision::Deny);
    }

    #[test]
    fn non_admin_allowed_on_low_risk() {
        let eng = CedarEngine::from_source(ADMIN_POLICY).expect("parse");
        let r = eng
            .evaluate(
                &alice(&["mcp-users"]),
                &Action::CallTool {
                    name: "example-messages.contacts.list".into(),
                    risk: RiskTier::Low,
                },
                &low_tool(),
            )
            .expect("eval");
        assert_eq!(r.decision, Decision::Allow);
    }

    /// A policy REMOVAL takes effect on a hot reload — no restart. The original
    /// ask was "policies and MCP servers hot-swap capable"; policies were already
    /// hot (atomic-swap via `ReloadableCedar`), but the previously-allowed →
    /// denied direction (a deleted `permit`) was untested. Mirrors
    /// `non_admin_allowed_on_low_risk` for the "before", then reloads a set with
    /// the low-risk `permit` removed and asserts the same call is now DENIED —
    /// proving the swap installs EXACTLY the new set (a removed permit stops
    /// allowing), not a union with the old one.
    #[test]
    fn removing_a_permit_takes_effect_on_reload() {
        use crate::{AuthzEngine, ReloadableCedar};

        // The low-risk `permit` (3rd rule of ADMIN_POLICY) lets a non-admin call
        // a low-risk tool.
        let rc = ReloadableCedar::new(CedarEngine::from_source(ADMIN_POLICY).expect("parse"));
        let call = Action::CallTool {
            name: "example-messages.contacts.list".into(),
            risk: RiskTier::Low,
        };
        assert_eq!(
            rc.evaluate(&alice(&["mcp-users"]), &call, &low_tool())
                .decision,
            Decision::Allow,
            "before removal, the low-risk permit allows the non-admin call",
        );

        // Hot-reload the SAME set with the low-risk permit deleted — only the
        // admin and SearchTools permits remain. No restart.
        const ADMIN_POLICY_NO_LOW_PERMIT: &str = r#"
            permit (principal in Group::"mcp-admins", action, resource);
            permit (principal, action == Action::"SearchTools", resource);
        "#;
        rc.reload(CedarEngine::from_source(ADMIN_POLICY_NO_LOW_PERMIT).expect("parse"));

        // After: the deleted permit no longer applies, so the same call is denied
        // — the removal took effect live, without a restart.
        assert_eq!(
            rc.evaluate(&alice(&["mcp-users"]), &call, &low_tool())
                .decision,
            Decision::Deny,
            "removing the low-risk permit denies the call after a hot reload",
        );
        // Sanity: the reload SWAPPED the set (not cleared it) — an unrelated
        // permit that survived still applies.
        assert_eq!(
            rc.evaluate(&alice(&["mcp-admins"]), &call, &low_tool())
                .decision,
            Decision::Allow,
            "a surviving permit still applies after the reload",
        );
    }

    #[test]
    fn tenant_policy_overrides_default_and_removal_restores_fallback() {
        use std::collections::HashMap;

        use crate::{AuthzEngine, ReloadableCedar};

        let rc = ReloadableCedar::new(
            CedarEngine::from_source("forbid (principal, action, resource);").expect("default"),
        );
        rc.replace_tenants(HashMap::from([(
            "acme".to_owned(),
            CedarEngine::from_source("permit (principal, action, resource);").expect("tenant"),
        )]));

        let call = Action::CallTool {
            name: "example-messages.contacts.list".into(),
            risk: RiskTier::Low,
        };
        let mut acme = alice(&["mcp-users"]);
        acme.tenant = waygate_core::TenantId::parse("acme").expect("tenant id");

        assert_eq!(
            rc.evaluate(&alice(&["mcp-users"]), &call, &low_tool())
                .decision,
            Decision::Deny,
            "the default tenant uses the default engine",
        );
        assert_eq!(
            rc.evaluate(&acme, &call, &low_tool()).decision,
            Decision::Allow,
            "a published tenant engine overrides the default engine",
        );

        assert!(rc.remove_tenant("acme"));
        assert_eq!(
            rc.evaluate(&acme, &call, &low_tool()).decision,
            Decision::Deny,
            "removing the tenant engine restores the documented default fallback",
        );
    }

    #[test]
    fn default_reload_preserves_tenant_engines() {
        use std::collections::HashMap;

        use crate::{AuthzEngine, ReloadableCedar};

        let rc = ReloadableCedar::new(
            CedarEngine::from_source("permit (principal, action, resource);").expect("default"),
        );
        rc.replace_tenants(HashMap::from([(
            "acme".to_owned(),
            CedarEngine::from_source("forbid (principal, action, resource);").expect("tenant"),
        )]));
        rc.reload(
            CedarEngine::from_source(
                "permit (principal, action, resource) when { principal.sub == \"alice\" };",
            )
            .expect("reloaded default"),
        );

        let mut acme = alice(&["mcp-users"]);
        acme.tenant = waygate_core::TenantId::parse("acme").expect("tenant id");
        assert_eq!(
            rc.evaluate(
                &acme,
                &Action::CallTool {
                    name: "example-messages.contacts.list".into(),
                    risk: RiskTier::Low,
                },
                &low_tool(),
            )
            .decision,
            Decision::Deny,
            "reloading the default file-backed engine must not discard tenant engines",
        );
    }

    #[test]
    fn tenant_diagnostics_and_scope_catalog_follow_the_serving_registry() {
        let default = CedarEngine::from_source(
            r#"@id("default")
permit(principal, action, resource)
when { principal.scopes.contains("scope:default") };"#,
        )
        .unwrap();
        let tenant = CedarEngine::from_source(
            r#"@id("tenant")
permit(principal, action, resource)
when { principal.scopes.contains("scope:tenant") };"#,
        )
        .unwrap();
        let reloadable = ReloadableCedar::new(default);
        reloadable.replace_tenants(HashMap::from([("acme".to_owned(), tenant)]));

        let tenant_policies = reloadable.list_policies_for_tenant("acme");
        assert_eq!(tenant_policies.len(), 1);
        assert_eq!(tenant_policies[0].id, "tenant");
        assert_eq!(
            reloadable.list_policies_for_tenant("missing")[0].id,
            "default",
            "diagnostic reads must use the same default fallback as evaluation",
        );
        assert_eq!(
            reloadable.referenced_scopes(),
            BTreeSet::from(["scope:default".to_owned(), "scope:tenant".to_owned()]),
            "scope reconciliation must include tenant-only policy references",
        );
    }

    /// Admin + step-up forbid: role-allow permits everything, but a separate
    /// forbid requires `mcp:invoke:high`. Without the scope, the first pass
    /// denies; the engine re-evaluates with the scope injected, sees the
    /// forbid drop out and the permit fire, and reports `StepUpRequired`.
    const STEP_UP_POLICY: &str = r#"
        permit (principal in Group::"mcp-admins", action, resource);
        permit (
            principal,
            action == Action::"CallTool",
            resource
        ) when { resource.risk == "low" };
        forbid (
            principal,
            action == Action::"CallTool",
            resource is Tool
        ) when {
            resource.risk == "high" &&
            !principal.scopes.contains("mcp:invoke:high")
        };
    "#;

    #[test]
    fn admin_without_scope_gets_step_up_on_high_risk() {
        let eng = CedarEngine::from_source(STEP_UP_POLICY).expect("parse");
        let r = eng
            .evaluate(
                &alice(&["mcp-admins"]),
                &Action::CallTool {
                    name: "example-messages.messages.send".into(),
                    risk: RiskTier::High,
                },
                &high_tool(),
            )
            .expect("eval");
        assert_eq!(r.decision, Decision::StepUpRequired);
        assert!(
            r.reasons.iter().any(|m| m.contains("mcp:invoke:high")),
            "reason should name the required scope: {:?}",
            r.reasons
        );
    }

    // A StepUpRequired decision must record the step-up
    // FORBID that fired in the real (first-pass) evaluation — the determinative
    // policy that required elevation — not the hypothetical scope-augmented
    // permit. Otherwise `audit_log.policy_ids` and the `/decisions?policy_id=`
    // reverse lookup can't answer "which decisions matched <step-up policy>".
    // Uses NAMED policies so the assertion pins stable ids, not positional ones.
    #[test]
    fn step_up_records_the_determinative_forbid_not_the_permit() {
        const NAMED_STEP_UP: &str = r#"
            @id("role-allow")
            permit (principal in Group::"mcp-admins", action, resource);
            @id("step-up-delete-dataset")
            forbid (
                principal,
                action == Action::"CallTool",
                resource is Tool
            ) when {
                resource.risk == "high" &&
                !principal.scopes.contains("mcp:invoke:high")
            };
        "#;
        let eng = CedarEngine::from_source(NAMED_STEP_UP).expect("parse");
        let r = eng
            .evaluate(
                &alice(&["mcp-admins"]),
                &Action::CallTool {
                    name: "example-messages.messages.send".into(),
                    risk: RiskTier::High,
                },
                &high_tool(),
            )
            .expect("eval");
        assert_eq!(r.decision, Decision::StepUpRequired);
        assert!(
            r.policy_ids.iter().any(|id| id == "step-up-delete-dataset"),
            "step-up must record the determinative forbid id; got {:?}",
            r.policy_ids
        );
        assert!(
            !r.policy_ids.iter().any(|id| id == "role-allow"),
            "step-up must NOT record the hypothetical scope-augmented permit; got {:?}",
            r.policy_ids
        );
    }

    #[test]
    fn admin_with_scope_allowed_on_high_risk_without_re_eval() {
        let mut admin = alice(&["mcp-admins"]);
        admin.scopes.push("mcp:invoke:high".into());
        let eng = CedarEngine::from_source(STEP_UP_POLICY).expect("parse");
        let r = eng
            .evaluate(
                &admin,
                &Action::CallTool {
                    name: "example-messages.messages.send".into(),
                    risk: RiskTier::High,
                },
                &high_tool(),
            )
            .expect("eval");
        assert_eq!(r.decision, Decision::Allow);
    }

    #[test]
    fn non_admin_still_denied_after_step_up_re_eval() {
        // Re-eval only flips the verdict when the augmented principal would
        // be allowed. A caller with no role permit gets a plain Deny, not
        // StepUpRequired — otherwise we'd leak "this tool exists and you
        // could access it" to every unauthenticated guess.
        let eng = CedarEngine::from_source(STEP_UP_POLICY).expect("parse");
        let r = eng
            .evaluate(
                &alice(&["mcp-users"]),
                &Action::CallTool {
                    name: "example-messages.messages.send".into(),
                    risk: RiskTier::High,
                },
                &high_tool(),
            )
            .expect("eval");
        assert_eq!(r.decision, Decision::Deny);
    }

    #[test]
    fn low_risk_call_never_triggers_step_up() {
        // `step_up_scope_for` returns None for Low, so the re-eval is skipped
        // even when the first pass denies. If this test ever flips to
        // StepUpRequired it means the engine is running re-eval on Low and
        // burning a second Cedar pass on every denied low-risk call.
        let policy = r#"
            permit (
                principal in Group::"mcp-admins",
                action == Action::"CallTool",
                resource
            );
        "#;
        let eng = CedarEngine::from_source(policy).expect("parse");
        let r = eng
            .evaluate(
                &alice(&["mcp-users"]),
                &Action::CallTool {
                    name: "example-messages.contacts.list".into(),
                    risk: RiskTier::Low,
                },
                &low_tool(),
            )
            .expect("eval");
        assert_eq!(r.decision, Decision::Deny);
    }

    /// EMA cross-app grant: ported text of `crates/waygate-authz/tests/fixtures/policies/40-cross-app-access.cedar`
    /// so its behaviour is enforced by Rust tests independent of the on-disk
    /// loader (same pattern as `PII_DEFAULT_POLICY` / `SCIM_ACTIVE_DEFAULT_POLICY`).
    /// Gates on the SCIM-authoritative `scim_groups` (NOT the token's
    /// `principal.groups`) — EMA grants must prove directory membership.
    const CROSS_APP_POLICY: &str = r#"
        permit (
            principal,
            action == Action::"GrantCrossAppAccess",
            resource
        ) when {
            principal.scim_present
            && principal.scim_active
            && principal.scim_groups.contains("mcp-users")
        };
    "#;

    /// Variant that also gates on the EMA client dimension via
    /// `context.client_id` — proves the client_id reaches Cedar's context.
    const CROSS_APP_CLIENT_POLICY: &str = r#"
        permit (
            principal,
            action == Action::"GrantCrossAppAccess",
            resource
        ) when {
            principal.scim_present
            && principal.scim_active
            && principal.scim_groups.contains("mcp-users")
            && context.client_id == "https://claude.ai/mcp.json"
        };
    "#;

    /// A SCIM-provisioned, active principal whose DIRECTORY groups
    /// (`scim_groups`) are set as given. The token-level `groups` is left
    /// empty, so a test using this proves the grant comes from SCIM
    /// membership and not a token claim.
    fn scim_member(scim_groups: &[&str]) -> Principal {
        let mut p = alice(&[]);
        p.scim = Some(waygate_oidc::ScimPrincipalAttrs {
            user_id: "u-1".into(),
            user_name: "alice".into(),
            external_id: None,
            active: true,
            attrs: serde_json::Value::Null,
            groups: scim_groups
                .iter()
                .enumerate()
                .map(|(i, g)| waygate_oidc::ScimGroupRef {
                    id: format!("g-{i}"),
                    display_name: (*g).to_string(),
                })
                .collect(),
        });
        p
    }

    #[test]
    fn grant_cross_app_access_permitted_for_scim_member() {
        let eng = CedarEngine::from_source(CROSS_APP_POLICY).expect("parse");
        let server = ResourceSpec::Server {
            name: "example-observability".into(),
        };
        // SCIM-provisioned, active, in the mcp-users DIRECTORY group → allow.
        let allow = eng
            .evaluate(
                &scim_member(&["mcp-users"]),
                &Action::GrantCrossAppAccess,
                &server,
            )
            .expect("eval");
        assert_eq!(allow.decision, Decision::Allow);

        // SCIM member but NOT in mcp-users → deny.
        let other = eng
            .evaluate(
                &scim_member(&["other"]),
                &Action::GrantCrossAppAccess,
                &server,
            )
            .expect("eval");
        assert_eq!(other.decision, Decision::Deny);

        // Token-claim mcp-users group but NO SCIM row → deny. EMA security
        // property: a top-level/token group must NOT authorize an ID-JAG;
        // only SCIM-authoritative membership does.
        let token_only = eng
            .evaluate(
                &alice(&["mcp-users"]),
                &Action::GrantCrossAppAccess,
                &server,
            )
            .expect("eval");
        assert_eq!(
            token_only.decision,
            Decision::Deny,
            "a token-claim mcp-users group with no SCIM row must NOT obtain an ID-JAG",
        );

        // SCIM member in mcp-users but DEACTIVATED → deny.
        let mut inactive = scim_member(&["mcp-users"]);
        inactive.scim.as_mut().unwrap().active = false;
        let deny_inactive = eng
            .evaluate(&inactive, &Action::GrantCrossAppAccess, &server)
            .expect("eval");
        assert_eq!(
            deny_inactive.decision,
            Decision::Deny,
            "a deactivated SCIM member must NOT obtain an ID-JAG",
        );
    }

    #[test]
    fn grant_cross_app_access_can_gate_on_client_id_context() {
        let eng = CedarEngine::from_source(CROSS_APP_CLIENT_POLICY).expect("parse");
        let server = ResourceSpec::Server {
            name: "example-observability".into(),
        };

        // Matching client_id in context → allowed.
        let mut ok = facts_from(
            &scim_member(&["mcp-users"]),
            &Action::GrantCrossAppAccess,
            &server,
        );
        ok.client.client_id = Some("https://claude.ai/mcp.json".into());
        assert_eq!(
            eng.evaluate_facts(&ok).expect("eval").decision,
            Decision::Allow,
            "matching context.client_id must satisfy the client-gated permit",
        );

        // Different client_id → denied (the client dimension is enforced).
        let mut wrong = facts_from(
            &scim_member(&["mcp-users"]),
            &Action::GrantCrossAppAccess,
            &server,
        );
        wrong.client.client_id = Some("https://evil.example/c.json".into());
        assert_eq!(
            eng.evaluate_facts(&wrong).expect("eval").decision,
            Decision::Deny,
            "a different client must not satisfy the client-gated permit",
        );

        // No client_id in context → the `context.client_id` reference can't
        // be satisfied, so the permit does not apply → deny.
        let none = facts_from(
            &scim_member(&["mcp-users"]),
            &Action::GrantCrossAppAccess,
            &server,
        );
        assert_eq!(
            eng.evaluate_facts(&none).expect("eval").decision,
            Decision::Deny,
            "absent client_id must not satisfy a client-gated permit",
        );
    }

    #[test]
    fn searchtools_allowed_for_everyone() {
        let eng = CedarEngine::from_source(ADMIN_POLICY).expect("parse");
        let r = eng
            .evaluate(
                &alice(&[]),
                &Action::SearchTools,
                &ResourceSpec::Server {
                    name: "example-messages".into(),
                },
            )
            .expect("eval");
        assert_eq!(r.decision, Decision::Allow);
    }

    /// The **core** PII forbid from `crates/waygate-authz/tests/fixtures/policies/15-pii-default.cedar` ported into
    /// a literal so the generic default behaviour (the `mcp-admins` /
    /// `pii-readers` exemption) is enforced by Rust tests, independent of the
    /// on-disk file loading path tested elsewhere. The on-disk file also carries
    /// synthetic, server-scoped role exemptions (e.g. `message-sender` /
    /// `message-reader`) that are covered by the policy golden tests, not
    /// this generic fixture.
    const PII_DEFAULT_POLICY: &str = r#"
        // Mirror the broad allow so the policy under test isn't the
        // only thing standing between every principal and every tool.
        permit (principal, action == Action::"CallTool", resource);

        forbid (
            principal,
            action == Action::"CallTool",
            resource
        )
        when {
            resource has pii && resource.pii && principal.auth_method == "api_key"
        }
        unless {
            principal has groups && (
                principal.groups.contains("mcp-admins")
                || principal.groups.contains("pii-readers")
            )
        };
    "#;

    #[test]
    fn pii_default_blocks_api_key_caller_on_pii_tool() {
        let eng = CedarEngine::from_source(PII_DEFAULT_POLICY).expect("parse");
        let r = eng
            .evaluate(
                &api_key_alice(&[]),
                &Action::CallTool {
                    name: "example-messages.messages.history".into(),
                    risk: RiskTier::Low,
                },
                &pii_tool(),
            )
            .expect("eval");
        assert_eq!(
            r.decision,
            Decision::Deny,
            "API-key caller on a PII tool must be forbidden by the default policy",
        );
    }

    #[test]
    fn pii_default_allows_api_key_caller_on_non_pii_tool() {
        // Same caller, same action — but `low_tool()` has pii=false.
        // The forbid clause's `resource.pii` is false, so the forbid
        // doesn't fire and the broad permit applies.
        let eng = CedarEngine::from_source(PII_DEFAULT_POLICY).expect("parse");
        let r = eng
            .evaluate(
                &api_key_alice(&[]),
                &Action::CallTool {
                    name: "example-messages.contacts.list".into(),
                    risk: RiskTier::Low,
                },
                &low_tool(),
            )
            .expect("eval");
        assert_eq!(r.decision, Decision::Allow);
    }

    #[test]
    fn pii_default_allows_oauth_caller_on_pii_tool() {
        // OAuth path is the supported access mode for PII tools.
        let eng = CedarEngine::from_source(PII_DEFAULT_POLICY).expect("parse");
        let r = eng
            .evaluate(
                &alice(&[]),
                &Action::CallTool {
                    name: "example-messages.messages.history".into(),
                    risk: RiskTier::Low,
                },
                &pii_tool(),
            )
            .expect("eval");
        assert_eq!(r.decision, Decision::Allow);
    }

    #[test]
    fn pii_default_unless_clause_allows_pii_readers_api_key() {
        // The explicit per-key opt-in: an API-key principal whose
        // subject is enrolled in the `pii-readers` group bypasses the
        // forbid. The mcp-admins group has the same effect — covered
        // by the broader admin-passthrough already.
        let eng = CedarEngine::from_source(PII_DEFAULT_POLICY).expect("parse");
        let r = eng
            .evaluate(
                &api_key_alice(&["pii-readers"]),
                &Action::CallTool {
                    name: "example-messages.messages.history".into(),
                    risk: RiskTier::Low,
                },
                &pii_tool(),
            )
            .expect("eval");
        assert_eq!(r.decision, Decision::Allow);
    }

    #[test]
    fn pii_attribute_lands_on_cedar_tool_entity() {
        // Cross-layer pin: a ToolSpec with pii=true produces a Cedar
        // Tool entity whose `pii` attribute is true and is reachable
        // from a policy. Independent of the four default-policy
        // tests above so a regression in the entity builder fails
        // with a clearer error.
        let policy = r#"
            permit (principal, action, resource) when { resource.pii };
        "#;
        let eng = CedarEngine::from_source(policy).expect("parse");

        let allowed = eng
            .evaluate(
                &alice(&[]),
                &Action::CallTool {
                    name: "example-messages.messages.history".into(),
                    risk: RiskTier::Low,
                },
                &pii_tool(),
            )
            .expect("eval");
        assert_eq!(
            allowed.decision,
            Decision::Allow,
            "pii=true tool must satisfy `resource.pii` in policy",
        );

        let denied = eng
            .evaluate(
                &alice(&[]),
                &Action::CallTool {
                    name: "example-messages.contacts.list".into(),
                    risk: RiskTier::Low,
                },
                &low_tool(),
            )
            .expect("eval");
        assert_eq!(
            denied.decision,
            Decision::Deny,
            "pii=false tool must not satisfy `resource.pii`",
        );
    }

    /// The user entity carries a `tenant` attribute
    /// stamped from `principal.tenant`. Pins the cross-layer
    /// invariant a tenant-scoped Cedar policy can reference. Two
    /// principals with the same sub but different tenants get
    /// different decisions under a tenant-filtered policy — the
    /// substrate the SCIM/RBAC work builds on.
    #[test]
    fn tenant_attribute_lands_on_cedar_user_entity() {
        let policy = r#"
            permit (principal, action, resource)
            when { principal.tenant == "acme-prod" };
        "#;
        let eng = CedarEngine::from_source(policy).expect("parse");

        // Default tenant: policy doesn't match.
        let denied = eng
            .evaluate(
                &alice(&[]),
                &Action::CallTool {
                    name: "example-messages.contacts.list".into(),
                    risk: RiskTier::Low,
                },
                &low_tool(),
            )
            .expect("eval");
        assert_eq!(
            denied.decision,
            Decision::Deny,
            "default-tenant principal must not satisfy `principal.tenant == \"acme-prod\"`",
        );

        // acme-prod tenant: policy matches.
        let mut acme = alice(&[]);
        acme.tenant = waygate_core::TenantId::parse("acme-prod").unwrap();
        let allowed = eng
            .evaluate(
                &acme,
                &Action::CallTool {
                    name: "example-messages.contacts.list".into(),
                    risk: RiskTier::Low,
                },
                &low_tool(),
            )
            .expect("eval");
        assert_eq!(
            allowed.decision,
            Decision::Allow,
            "acme-prod principal must satisfy `principal.tenant == \"acme-prod\"`",
        );
    }

    /// SCIM-resolved attrs flow through `facts_from`
    /// into the Cedar entity. Policies can write:
    ///   `principal.scim_present && principal.scim_active &&
    ///    principal.scim_groups.contains("admins")`
    /// to gate on SCIM-provisioned group membership distinct from
    /// JWT-emitted groups. Two principals with the same JWT shape
    /// but different `Principal.scim` must produce different
    /// decisions under a SCIM-gated policy.
    #[test]
    fn scim_attrs_land_on_cedar_user_entity() {
        let policy = r#"
            permit (principal, action, resource)
            when {
                principal.scim_present
                && principal.scim_active
                && principal.scim_groups.contains("admins")
            };
        "#;
        let eng = CedarEngine::from_source(policy).expect("parse");

        // Principal without SCIM enrichment: `scim_present == false`,
        // policy denies.
        let denied = eng
            .evaluate(
                &alice(&[]),
                &Action::CallTool {
                    name: "example-messages.contacts.list".into(),
                    risk: RiskTier::Low,
                },
                &low_tool(),
            )
            .expect("eval");
        assert_eq!(denied.decision, Decision::Deny);

        // Principal WITH SCIM enrichment, active=true, in "admins":
        // policy permits.
        let mut enriched = alice(&[]);
        enriched.scim = Some(waygate_oidc::ScimPrincipalAttrs {
            user_id: "u-1".into(),
            user_name: "alice".into(),
            external_id: None,
            active: true,
            attrs: serde_json::Value::Null,
            groups: vec![
                waygate_oidc::ScimGroupRef {
                    id: "g-1".into(),
                    display_name: "admins".into(),
                },
                waygate_oidc::ScimGroupRef {
                    id: "g-2".into(),
                    display_name: "finance".into(),
                },
            ],
        });
        let allowed = eng
            .evaluate(
                &enriched,
                &Action::CallTool {
                    name: "example-messages.contacts.list".into(),
                    risk: RiskTier::Low,
                },
                &low_tool(),
            )
            .expect("eval");
        assert_eq!(allowed.decision, Decision::Allow);

        // Same enriched principal but active=false: policy denies
        // — pins the spec-required behaviour that deactivated SCIM
        // users are denied even when otherwise in the right group.
        let mut deactivated = enriched.clone();
        deactivated.scim.as_mut().unwrap().active = false;
        let denied_inactive = eng
            .evaluate(
                &deactivated,
                &Action::CallTool {
                    name: "example-messages.contacts.list".into(),
                    risk: RiskTier::Low,
                },
                &low_tool(),
            )
            .expect("eval");
        assert_eq!(
            denied_inactive.decision,
            Decision::Deny,
            "deactivated SCIM user (active=false) must be denied",
        );
    }

    /// Ported text of
    /// `crates/waygate-authz/tests/fixtures/policies/16-scim-active.cedar`
    /// (the SCIM-deactivation default policy) into a literal so its
    /// behaviour is enforced by Rust tests, independent of the
    /// on-disk loader. Same pattern as `PII_DEFAULT_POLICY`.
    const SCIM_ACTIVE_DEFAULT_POLICY: &str = r#"
        // Mirror a broad permit so the policy under test isn't the
        // only thing between every principal and every tool.
        permit (principal, action, resource);

        forbid (principal, action, resource)
        when {
            principal.scim_present && !principal.scim_active
        };
    "#;

    fn scim_principal(active: bool) -> Principal {
        let mut p = alice(&[]);
        p.scim = Some(waygate_oidc::ScimPrincipalAttrs {
            user_id: "u-1".into(),
            user_name: "alice".into(),
            external_id: None,
            active,
            attrs: serde_json::Value::Null,
            groups: vec![],
        });
        p
    }

    #[test]
    fn scim_active_default_allows_active_principal() {
        let eng = CedarEngine::from_source(SCIM_ACTIVE_DEFAULT_POLICY).expect("parse");
        let r = eng
            .evaluate(
                &scim_principal(true),
                &Action::CallTool {
                    name: "example-messages.contacts.list".into(),
                    risk: RiskTier::Low,
                },
                &low_tool(),
            )
            .expect("eval");
        assert_eq!(
            r.decision,
            Decision::Allow,
            "active SCIM user must pass the deactivation default",
        );
    }

    #[test]
    fn scim_active_default_denies_inactive_principal() {
        let eng = CedarEngine::from_source(SCIM_ACTIVE_DEFAULT_POLICY).expect("parse");
        let r = eng
            .evaluate(
                &scim_principal(false),
                &Action::CallTool {
                    name: "example-messages.contacts.list".into(),
                    risk: RiskTier::Low,
                },
                &low_tool(),
            )
            .expect("eval");
        assert_eq!(
            r.decision,
            Decision::Deny,
            "deactivated SCIM user (active=false) must be denied by the default",
        );
    }

    /// Principals not provisioned via SCIM (no enricher OR no
    /// matching row) MUST still flow through the deactivation
    /// default unaffected. Without the `scim_present` guard, the
    /// rule's `!principal.scim_active` would evaluate to true on
    /// a default-built `principal.scim_active = false`, locking
    /// out every non-SCIM caller.
    #[test]
    fn scim_active_default_does_not_block_non_scim_principal() {
        let eng = CedarEngine::from_source(SCIM_ACTIVE_DEFAULT_POLICY).expect("parse");
        let r = eng
            .evaluate(
                &alice(&[]), // no .scim set
                &Action::CallTool {
                    name: "example-messages.contacts.list".into(),
                    risk: RiskTier::Low,
                },
                &low_tool(),
            )
            .expect("eval");
        assert_eq!(
            r.decision,
            Decision::Allow,
            "non-SCIM principal must NOT be denied by the SCIM deactivation default",
        );
    }

    /// Custom SCIM JSONB attrs flow
    /// into the Cedar User entity as a nested `scim_attrs` record
    /// so policies can write
    /// `principal has scim_attrs && principal.scim_attrs.department == "..."`.
    #[test]
    fn scim_custom_attrs_flatten_into_cedar_record() {
        let policy = r#"
            permit (principal, action, resource)
            when {
                principal has scim_attrs
                && principal.scim_attrs has department
                && principal.scim_attrs.department == "engineering"
            };
        "#;
        let eng = CedarEngine::from_source(policy).expect("parse");

        let mut allowed = alice(&[]);
        allowed.scim = Some(waygate_oidc::ScimPrincipalAttrs {
            user_id: "u".into(),
            user_name: "alice".into(),
            external_id: None,
            active: true,
            attrs: serde_json::json!({
                "department": "engineering",
                "costCenter": 1234,
                "tags": ["lead", "oncall"],
                "address": { "city": "NYC" },
                "tenure_years": 3.5
            }),
            groups: vec![],
        });
        let r = eng
            .evaluate(
                &allowed,
                &Action::CallTool {
                    name: "example-messages.contacts.list".into(),
                    risk: RiskTier::Low,
                },
                &low_tool(),
            )
            .expect("eval");
        assert_eq!(
            r.decision,
            Decision::Allow,
            "principal with scim_attrs.department=engineering must satisfy the policy",
        );

        let mut denied = allowed.clone();
        denied.scim.as_mut().unwrap().attrs = serde_json::json!({"department": "sales"});
        let r = eng
            .evaluate(
                &denied,
                &Action::CallTool {
                    name: "example-messages.contacts.list".into(),
                    risk: RiskTier::Low,
                },
                &low_tool(),
            )
            .expect("eval");
        assert_eq!(
            r.decision,
            Decision::Deny,
            "principal whose scim_attrs.department != \"engineering\" must NOT satisfy the policy",
        );
    }

    /// Ambiguous SCIM matches must
    /// trigger the `scim_blocks_request()` deny path.
    #[test]
    fn enrichment_blocked_triggers_scim_blocks_request() {
        let mut p = alice(&[]);
        p.enrichment_blocked = Some("scim_ambiguous_match:2".into());
        assert!(
            p.scim_blocks_request(),
            "enrichment_blocked must surface through scim_blocks_request()",
        );
    }

    /// RBAC-resolved role names lift into the Cedar
    /// User entity as a set `principal.roles`. A policy gating on
    /// `principal.roles.contains("tenant_admin")` permits the
    /// admin and denies a peer who lacks the role.
    #[test]
    fn rbac_roles_land_on_cedar_user_entity() {
        let policy = r#"
            permit (principal, action, resource)
            when { principal.roles.contains("tenant_admin") };
        "#;
        let eng = CedarEngine::from_source(policy).expect("parse");

        let denied = eng
            .evaluate(
                &alice(&[]),
                &Action::CallTool {
                    name: "example-messages.contacts.list".into(),
                    risk: RiskTier::Low,
                },
                &low_tool(),
            )
            .expect("eval");
        assert_eq!(denied.decision, Decision::Deny);

        let mut with_role = alice(&[]);
        with_role.roles = vec!["tenant_admin".into()];
        let allowed = eng
            .evaluate(
                &with_role,
                &Action::CallTool {
                    name: "example-messages.contacts.list".into(),
                    risk: RiskTier::Low,
                },
                &low_tool(),
            )
            .expect("eval");
        assert_eq!(allowed.decision, Decision::Allow);
    }

    // Pin the real Cedar path that "explain this denial"
    // relies on — `@reason("...")` annotations on fired
    // forbid policies must populate `AuthzResult.reasons`.
    // Exercises the real `evaluate_raw_facts` path (not a
    // fake `AuthzVerdict::Deny`): `reasons` must never be
    // sourced from `diagnostics().errors()` (engine
    // evaluation errors), which are empty for ordinary
    // forbids.
    #[test]
    fn deny_surfaces_policy_reason_annotation() {
        let src = r#"
            @reason("forbids: principal not in mcp-admins group")
            forbid (
                principal,
                action == Action::"CallTool",
                resource
            ) when { !(principal in Group::"mcp-admins") };
        "#;
        let eng = CedarEngine::from_source(src).expect("parse");
        let r = eng
            .evaluate(
                &alice(&[]),
                &Action::CallTool {
                    name: "example-messages.contacts.list".into(),
                    risk: RiskTier::Low,
                },
                &low_tool(),
            )
            .expect("eval");
        assert_eq!(r.decision, Decision::Deny);
        assert!(
            !r.policy_ids.is_empty(),
            "fired policy must appear in policy_ids"
        );
        assert_eq!(
            r.reasons,
            vec!["forbids: principal not in mcp-admins group".to_owned()],
            "@reason annotation must propagate through to AuthzResult.reasons; previous \
             code sourced from diagnostics().errors() and emitted [] on ordinary forbids"
        );
    }

    // Forbid-overlay premise (1/2): an operator `forbid` keyed on
    // `resource.server == "gateway-control"` fires for a built-in control-plane
    // tool and lands in `policy_ids`, EVEN for an mcp-admins principal the
    // ADMIN_POLICY permit would otherwise allow (forbid overrides permit). The
    // dispatch overlay reads exactly this — a Deny with non-empty `policy_ids`
    // is its "block" signal — so this pins the engine half of that contract for
    // the reserved namespace specifically.
    #[test]
    fn forbid_on_gateway_control_fires_with_policy_ids_even_for_admin() {
        let src = format!(
            "{ADMIN_POLICY}\n\
             forbid (principal, action == Action::\"CallTool\", resource)\n\
             when {{ resource.server == \"gateway-control\" }};"
        );
        let eng = CedarEngine::from_source(&src).expect("parse");
        let r = eng
            .evaluate(
                &alice(&["mcp-admins"]),
                &Action::CallTool {
                    name: "gateway-control.quarantine_server".into(),
                    risk: RiskTier::High,
                },
                &control_tool(),
            )
            .expect("eval");
        assert_eq!(
            r.decision,
            Decision::Deny,
            "the forbid must override the admin permit"
        );
        assert!(
            !r.policy_ids.is_empty(),
            "a determining forbid must populate policy_ids (the overlay's block signal)"
        );
    }

    // Forbid-overlay premise (2/2, the no-lockout half): when NO policy
    // mentions the built-in namespace, a high-risk control tool denies by
    // BASELINE (no permit matches a non-admin) with an EMPTY `policy_ids`. The
    // overlay treats empty policy_ids as "not a block" so an ungoverned built-in
    // is never locked out by the absence of a permit — the scope floor governs.
    #[test]
    fn ungoverned_gateway_control_denies_by_baseline_with_empty_policy_ids() {
        let eng = CedarEngine::from_source(ADMIN_POLICY).expect("parse");
        let r = eng
            .evaluate(
                &alice(&[]),
                &Action::CallTool {
                    name: "gateway-control.quarantine_server".into(),
                    risk: RiskTier::High,
                },
                &control_tool(),
            )
            .expect("eval");
        assert_eq!(r.decision, Decision::Deny);
        assert!(
            r.policy_ids.is_empty(),
            "an ungoverned built-in must deny by baseline (empty policy_ids), not a forbid — \
             this is what lets the overlay proceed and the scope floor govern"
        );
    }

    // A built-in governance policy that ERRORS at evaluation (undefined
    // attr) contributes no policy_ids — it is indistinguishable from a clean
    // baseline deny, so an overlay reading only the decision would proceed and
    // FAIL OPEN. Both the STRICT path used by the built-in overlay and the
    // lenient tool plane must refuse the request instead.
    #[test]
    fn builtin_strict_path_fails_closed_on_policy_evaluation_error() {
        use crate::{AuthzEngine, AuthzOutcome};

        let src = r#"
            forbid (principal, action == Action::"CallTool", resource)
            when { principal.no_such_attr == "x" };
        "#;
        let eng = CedarEngine::from_source(src).expect("parse");
        let facts = facts_from(
            &alice(&[]),
            &Action::CallTool {
                name: "gateway-control.quarantine_server".into(),
                risk: RiskTier::High,
            },
            &control_tool(),
        );

        // Strict path (built-in overlay): the evaluation error fails closed.
        match <CedarEngine as AuthzEngine>::try_evaluate_facts(&eng, &facts) {
            AuthzOutcome::EngineError => {}
            AuthzOutcome::Decided(r) => panic!(
                "a policy evaluation error must fail closed on the strict path, got Decided({:?})",
                r.decision
            ),
        }

        // Lenient path (upstream tool plane): the erroring forbid is a dropped
        // restriction, so the request is refused rather than decided without it.
        assert!(
            matches!(eng.evaluate_facts(&facts), Err(CedarError::Eval(_))),
            "an erroring forbid must fail the lenient evaluation, not be skipped"
        );
        let lenient = <CedarEngine as AuthzEngine>::evaluate_facts(&eng, &facts);
        assert_eq!(
            lenient.decision,
            Decision::Deny,
            "the trait boundary maps that engine error to a fail-closed deny"
        );
    }

    /// The bypass this whole treatment exists to close: a `forbid` whose
    /// condition errors is skipped by Cedar, so a matching `permit` decides the
    /// request and the operator's restriction silently evaporates. On the tool
    /// plane — which authorizes every upstream call — that is an authorization
    /// bypass, so an unevaluatable forbid must deny instead of allow.
    #[test]
    fn erroring_forbid_does_not_let_a_matching_permit_allow() {
        use crate::AuthzEngine;

        // `principal.no_such_attr` is absent from the entity, so the forbid
        // errors; the low-risk permit matches and would otherwise decide Allow.
        let src = r#"
            permit (principal, action == Action::"CallTool", resource)
            when { resource.risk == "low" };

            forbid (principal, action == Action::"CallTool", resource)
            when { principal.no_such_attr == "x" };
        "#;
        let eng = CedarEngine::from_source(src).expect("parse");
        let facts = facts_from(
            &alice(&[]),
            &Action::CallTool {
                name: "example-messages.contacts.list".into(),
                risk: RiskTier::Low,
            },
            &low_tool(),
        );

        assert_ne!(
            <CedarEngine as AuthzEngine>::evaluate_facts(&eng, &facts).decision,
            Decision::Allow,
            "a forbid that could not be evaluated must not be dropped in favour of a permit",
        );
    }

    /// The other half of the contract: an erroring `permit` is NOT fail-closed.
    /// Cedar skipping a permit can only remove an allow, which default-deny
    /// already covers, so one broken permit must not deny traffic the rest of
    /// the set still governs.
    #[test]
    fn erroring_permit_still_yields_a_decision() {
        let src = r#"
            permit (principal, action == Action::"CallTool", resource)
            when { principal.no_such_attr == "x" };

            permit (principal, action == Action::"CallTool", resource)
            when { resource.risk == "low" };
        "#;
        let eng = CedarEngine::from_source(src).expect("parse");
        let facts = facts_from(
            &alice(&[]),
            &Action::CallTool {
                name: "example-messages.contacts.list".into(),
                risk: RiskTier::Low,
            },
            &low_tool(),
        );

        assert_eq!(
            eng.evaluate_facts(&facts).expect("eval").decision,
            Decision::Allow,
            "a skipped permit must not fail the evaluation of the surviving set",
        );
    }

    // Engine diagnostic errors (Cedar evaluation errors — type
    // mismatches, undefined attrs) MUST NOT leak into client-visible `reasons`,
    // even though the same `diagnostics().errors()` channel
    // populates them. The fail-closed path in
    // `AuthzEngine for CedarEngine` already drops the error
    // message; this test pins that `evaluate_raw_facts`
    // similarly does not surface evaluation errors.
    #[test]
    fn engine_errors_do_not_leak_into_reasons() {
        use crate::AuthzEngine;

        // A policy that references an undefined attribute on the principal —
        // Cedar raises an evaluation error at request time. A `permit` is used
        // so the evaluation still returns a decision (an erroring forbid is
        // refused outright), which is the case where `reasons` is populated at
        // all. The point of the test isn't the verdict but that `reasons` stays
        // free of engine internals regardless of what Cedar emits via
        // `diagnostics().errors()`.
        let src = r#"
            @reason("only annotations may reach a caller")
            permit (
                principal,
                action,
                resource
            ) when { principal.no_such_attr == "x" };
        "#;
        let eng = CedarEngine::from_source(src).expect("parse");
        let r = eng
            .evaluate(&alice(&[]), &Action::SearchTools, &low_tool())
            .expect("eval");
        // Whatever Cedar reports, no engine error string
        // should appear in `reasons` — they must come from
        // policy `@reason` annotations only.
        for reason in &r.reasons {
            assert!(
                !reason.starts_with("engine error")
                    && !reason.to_ascii_lowercase().contains("error"),
                "engine diagnostics leaked into client-visible reasons: {reason:?}",
            );
        }

        // The fail-closed forbid path is the other way an evaluation error can
        // reach a caller: it must surface as a bare deny carrying no diagnostic
        // text at all.
        let forbidding = CedarEngine::from_source(
            r#"forbid (principal, action, resource) when { principal.no_such_attr == "x" };"#,
        )
        .expect("parse");
        let denied = <CedarEngine as AuthzEngine>::evaluate(
            &forbidding,
            &alice(&[]),
            &Action::SearchTools,
            &low_tool(),
        );
        assert_eq!(denied.decision, Decision::Deny);
        assert!(
            denied.reasons.is_empty(),
            "the fail-closed deny must not carry engine diagnostics: {:?}",
            denied.reasons,
        );
    }

    // ---- Stable-id annotations + loader provenance ----

    #[test]
    fn from_source_rekeys_policy_id_from_annotation() {
        let eng = CedarEngine::from_source(
            r#"@id("my-rule") permit (principal, action == Action::"SearchTools", resource);"#,
        )
        .expect("parse");
        let snaps = eng.list_policies();
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].id, "my-rule");
    }

    #[test]
    fn from_source_without_id_keeps_positional() {
        // Un-annotated fragments (dev mode, not-yet-migrated bundles) still
        // load, keeping Cedar's positional id.
        let eng = CedarEngine::from_source(
            r#"permit (principal, action == Action::"SearchTools", resource);"#,
        )
        .expect("parse");
        let snaps = eng.list_policies();
        assert_eq!(snaps.len(), 1);
        assert!(
            snaps[0].id.starts_with("policy"),
            "expected positional fallback id, got {:?}",
            snaps[0].id
        );
    }

    #[test]
    fn duplicate_id_annotation_is_rejected() {
        // Two policies sharing an @id would make policy_ids ambiguous in the
        // simulator and audit; the loader must refuse the whole set.
        // `CedarEngine` is not `Debug`, so match rather than `expect_err`.
        let err = match CedarEngine::from_source(
            r#"
            @id("dup") permit (principal, action == Action::"ListTools", resource);
            @id("dup") permit (principal, action == Action::"SearchTools", resource);
            "#,
        ) {
            Ok(_) => panic!("duplicate @id must fail to load"),
            Err(e) => e,
        };
        assert!(
            matches!(err, CedarError::DuplicateId(ref id) if id == "dup"),
            "expected DuplicateId(\"dup\"), got {err:?}"
        );
    }

    #[test]
    fn snapshot_surfaces_layer_description_tags_reason() {
        let eng = CedarEngine::from_source(
            r#"
            @id("r")
            @layer("pii-overlay")
            @description("desc text")
            @tags("a, b ,c")
            @reason("why")
            forbid (principal, action, resource) when { resource has pii && resource.pii };
            "#,
        )
        .expect("parse");
        let s = &eng.list_policies()[0];
        assert_eq!(s.layer.as_deref(), Some("pii-overlay"));
        assert_eq!(s.description.as_deref(), Some("desc text"));
        assert_eq!(s.tags, vec!["a", "b", "c"]);
        assert_eq!(s.reason.as_deref(), Some("why"));
    }

    /// Re-keyed ids must flow into the evaluation `policy_ids` — that linkage is
    /// the whole point (deep-link a fired policy, query the decision log). A
    /// fired forbid carrying `@id("x")` must report `x`, not `policy0`.
    #[test]
    fn fired_policy_reports_its_stable_id() {
        let eng = CedarEngine::from_source(
            r#"
            @id("forbid-search")
            forbid (principal, action == Action::"SearchTools", resource);
            "#,
        )
        .expect("parse");
        let r = eng
            .evaluate(&alice(&[]), &Action::SearchTools, &low_tool())
            .expect("eval");
        assert_eq!(r.decision, Decision::Deny);
        assert!(
            r.policy_ids.iter().any(|id| id == "forbid-search"),
            "fired policy must report its @id, got {:?}",
            r.policy_ids
        );
    }

    /// GUARD (mirrors `scripts/check-policy-annotations.sh`): every shipped
    /// policy under `policies/` MUST carry a stable `@id` and a `@layer`. Runs
    /// under `cargo test`, so PR CI and the image build both block on it — the
    /// same belt-and-suspenders pattern as the migration_versions guard. A
    /// successful `load_dir` already proves @id uniqueness (the loader errors on
    /// a duplicate); this additionally proves completeness.
    #[test]
    fn every_on_disk_policy_has_stable_id_and_layer() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/policies");
        let eng = CedarEngine::load_dir(&dir)
            .unwrap_or_else(|e| panic!("load shipped policies/ at {}: {e}", dir.display()));
        let snaps = eng.list_policies();
        assert!(
            !snaps.is_empty(),
            "no policies loaded from {}",
            dir.display()
        );

        let mut ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        for s in &snaps {
            assert!(
                !is_positional_id(&s.id),
                "policy is missing an @id annotation (got positional `{}`):\n{}",
                s.id,
                s.source
            );
            assert!(
                s.layer.as_deref().is_some_and(|l| !l.is_empty()),
                "policy `{}` is missing a @layer annotation",
                s.id
            );
            assert!(ids.insert(s.id.clone()), "duplicate policy id `{}`", s.id);
        }
    }

    fn is_positional_id(id: &str) -> bool {
        id.strip_prefix("policy")
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
    }

    /// The representative fixture set concatenated the way `load_dir` composes
    /// it (sorted by filename, each followed by a newline).
    fn combined_on_disk_policies() -> String {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/policies");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("read policies dir {}: {e}", dir.display()))
            .filter_map(|r| r.ok())
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("cedar"))
            .map(|e| e.path())
            .collect();
        files.sort();
        let mut combined = String::new();
        for p in files {
            combined.push_str(&std::fs::read_to_string(p).unwrap());
            combined.push('\n');
        }
        combined
    }

    #[test]
    fn validate_diagnostics_empty_on_valid_policy() {
        assert!(
            validate_diagnostics("@id(\"a\")\npermit(principal, action, resource);").is_empty()
        );
        // The complete representative fixture set parses clean too.
        let combined = combined_on_disk_policies();
        assert!(validate_diagnostics(&combined).is_empty());
    }

    #[test]
    fn validate_diagnostics_flags_a_parse_error_with_position() {
        // `permitt` is not a Cedar keyword → a parse error. We assert the
        // contract (≥1 diagnostic, on a sensible line, with a message), not the
        // exact parser wording, which is cedar-policy's to change.
        let src = "@id(\"a\")\npermitt(principal, action, resource);";
        let diags = validate_diagnostics(src);
        assert!(!diags.is_empty(), "a parse error must produce a diagnostic");
        let d = &diags[0];
        assert!(d.line >= 1 && d.col >= 1, "1-based position");
        assert!(d.end_line >= d.line, "end is at or after start");
        assert!(!d.message.is_empty(), "diagnostic carries a message");
        // The error is on the second line (the `permitt` statement), not line 1.
        assert_eq!(d.line, 2, "diagnostic points at the offending line");
    }

    #[test]
    fn validate_diagnostics_flags_duplicate_id_like_from_source() {
        // `PolicySet::from_str` accepts duplicate @id (metadata), but
        // `from_source`'s re-keying rejects it — and so must Save/Validate. The
        // gutter must flag it too, pointed at the SECOND (colliding) @id.
        let src = "@id(\"dup\")\npermit(principal, action, resource);\n\
            @id(\"dup\")\nforbid(principal, action, resource);";
        // Sanity: from_source rejects this, from_str alone does not.
        assert!(PolicySet::from_str(src).is_ok());
        assert!(CedarEngine::from_source(src).is_err());

        let diags = validate_diagnostics(src);
        assert_eq!(diags.len(), 1, "one duplicate-id diagnostic");
        assert!(
            diags[0].message.contains("duplicate @id \"dup\""),
            "{}",
            diags[0].message
        );
        assert_eq!(diags[0].line, 3, "points at the colliding (second) @id");
    }

    #[test]
    fn offset_to_line_col_maps_multiline() {
        let src = "ab\ncde\nf"; // lines: 1="ab"(0..2,\n@2), 2="cde"(3..6,\n@6), 3="f"(7)
        assert_eq!(offset_to_line_col(src, 0), (1, 1)); // 'a'
        assert_eq!(offset_to_line_col(src, 1), (1, 2)); // 'b'
        assert_eq!(offset_to_line_col(src, 3), (2, 1)); // 'c'
        assert_eq!(offset_to_line_col(src, 5), (2, 3)); // 'e'
        assert_eq!(offset_to_line_col(src, 7), (3, 1)); // 'f'
                                                        // Clamped past the end.
        assert_eq!(offset_to_line_col(src, 999), (3, 2));
    }

    /// The legacy Code Mode approval overlay retained for compatibility tests:
    /// a forbid conditioned on the gateway-stamped legacy channel and the
    /// absence of a live approval grant.
    const CODEMODE_APPROVAL_POLICY: &str = r#"
        @id("role-allow")
        permit (
            principal in Group::"mcp-users",
            action == Action::"CallTool",
            resource
        );
        @id("codemode-mutation-approval")
        forbid (
            principal,
            action == Action::"CallTool",
            resource is Tool
        ) when {
            context.channel == "codemode" &&
            resource.side_effects &&
            !context.approval_present
        };
    "#;

    fn codemode_call_facts(groups: &[&str], side_effects: bool) -> Facts {
        let mut facts = facts_from(
            &alice(groups),
            &Action::CallTool {
                name: "example-messages.messages.send".into(),
                risk: RiskTier::Low,
            },
            &ResourceSpec::Tool(ToolSpec {
                operation: None,
                server: "example-messages".into(),
                name: "send_msg".into(),
                risk: RiskTier::Low,
                side_effects,
                pii: false,
            }),
        );
        facts.context.channel = waygate_core::InvocationChannelFact::CodeMode;
        facts
    }

    // The engine's approval inference: a permitted caller whose only
    // obstacle is the approval overlay gets ApprovalRequired — carrying the
    // determinative overlay forbid id — so the invocation pipeline can gate
    // dispatch on a grant claim instead of flatly denying.
    #[test]
    fn codemode_side_effect_reports_approval_required_with_the_overlay_id() {
        let eng = CedarEngine::from_source(CODEMODE_APPROVAL_POLICY).expect("parse");
        let r = eng
            .evaluate_facts(&codemode_call_facts(&["mcp-users"], true))
            .expect("eval");
        assert_eq!(r.decision, Decision::ApprovalRequired);
        assert_eq!(
            r.policy_ids,
            vec!["codemode-mutation-approval".to_owned()],
            "the determinative first-pass forbid is recorded, not the permit",
        );
    }

    // The overlay keys on the gateway-stamped channel: the same principal
    // calling the same side-effecting tool directly is untouched.
    #[test]
    fn direct_channel_calls_are_untouched_by_the_codemode_overlay() {
        let eng = CedarEngine::from_source(CODEMODE_APPROVAL_POLICY).expect("parse");
        let mut facts = codemode_call_facts(&["mcp-users"], true);
        facts.context.channel = waygate_core::InvocationChannelFact::Direct;
        let r = eng.evaluate_facts(&facts).expect("eval");
        assert_eq!(r.decision, Decision::Allow);
    }

    // Approval inference must never widen authorization: a caller without
    // the underlying permit stays flatly denied, so ApprovalRequired can
    // only ever narrow an allow behind a grant.
    #[test]
    fn approval_inference_requires_an_underlying_permit() {
        let eng = CedarEngine::from_source(CODEMODE_APPROVAL_POLICY).expect("parse");
        let r = eng
            .evaluate_facts(&codemode_call_facts(&["strangers"], true))
            .expect("eval");
        assert_eq!(r.decision, Decision::Deny);
    }

    // Read-only Code Mode calls never hit the overlay: `resource.
    // side_effects` is part of the forbid condition.
    #[test]
    fn codemode_reads_are_not_approval_gated() {
        let eng = CedarEngine::from_source(CODEMODE_APPROVAL_POLICY).expect("parse");
        let r = eng
            .evaluate_facts(&codemode_call_facts(&["mcp-users"], false))
            .expect("eval");
        assert_eq!(r.decision, Decision::Allow);
    }

    // With a live grant reflected in context, the overlay's escape hatch
    // holds and the call evaluates Allow on the first pass — the policy
    // semantics the pipeline's grant claim stands in for.
    #[test]
    fn a_present_approval_grant_satisfies_the_overlay() {
        let eng = CedarEngine::from_source(CODEMODE_APPROVAL_POLICY).expect("parse");
        let mut facts = codemode_call_facts(&["mcp-users"], true);
        facts.context.approval_present = true;
        let r = eng.evaluate_facts(&facts).expect("eval");
        assert_eq!(r.decision, Decision::Allow);
    }

    // Both shipped gates on one call — a step-up rule AND the approval
    // overlay — must ladder, not collapse into a flat deny: the caller is
    // told to step up first, and once re-authorized the approval inference
    // surfaces the grant requirement.
    #[test]
    fn stacked_step_up_and_approval_overlays_ladder_instead_of_flat_deny() {
        const BOTH_OVERLAYS: &str = r#"
            @id("role-allow")
            permit (
                principal in Group::"mcp-users",
                action == Action::"CallTool",
                resource
            );
            @id("step-up-send")
            forbid (
                principal,
                action == Action::"CallTool",
                resource is Tool
            ) when {
                resource.name == "send_msg" &&
                !principal.scopes.contains("mcp:invoke:high")
            };
            @id("codemode-mutation-approval")
            forbid (
                principal,
                action == Action::"CallTool",
                resource is Tool
            ) when {
                context.channel == "codemode" &&
                resource.side_effects &&
                !context.approval_present
            };
        "#;
        let eng = CedarEngine::from_source(BOTH_OVERLAYS).expect("parse");
        let mut facts = facts_from(
            &alice(&["mcp-users"]),
            &Action::CallTool {
                name: "example-messages.messages.send".into(),
                risk: RiskTier::High,
            },
            &high_tool(),
        );
        facts.context.channel = waygate_core::InvocationChannelFact::CodeMode;
        // No step-up scope: both gates fire; the caller is guided to
        // re-authorize first.
        let r = eng.evaluate_facts(&facts).expect("eval");
        assert_eq!(r.decision, Decision::StepUpRequired);

        // With the scope: the approval gate is the only obstacle left.
        facts.principal.scopes.push("mcp:invoke:high".into());
        let r = eng.evaluate_facts(&facts).expect("eval");
        assert_eq!(r.decision, Decision::ApprovalRequired);
    }

    /// A native resource read reaches the approval inference too, so an
    /// approval-gated resource reports as approval-gated rather than
    /// collapsing into an ordinary denial the caller cannot tell apart. The
    /// gate that decides this lives in the engine, not in the read path, so it
    /// is pinned here: narrowing it back to tool calls must fail a test rather
    /// than silently downgrade every approval-gated resource to a flat Deny.
    #[test]
    fn an_approval_overlay_gates_a_resource_read_as_approval_required() {
        const RESOURCE_APPROVAL_OVERLAY: &str = r#"
            @id("permit-resource")
            permit (
                principal,
                action == Action::"ReadResource",
                resource
            );
            @id("approval-resource")
            forbid (
                principal,
                action == Action::"ReadResource",
                resource
            ) when {
                !context.approval_present
            };
        "#;
        let eng = CedarEngine::from_source(RESOURCE_APPROVAL_OVERLAY).expect("parse");
        let facts = facts_from(
            &alice(&["mcp-users"]),
            &Action::ReadResource {
                uri: "example-catalog://example-guides/design-v1".into(),
            },
            &ResourceSpec::McpResource {
                server: "example-catalog".into(),
                uri: "example-catalog://example-guides/design-v1".into(),
                risk: RiskTier::Low,
            },
        );

        let r = eng.evaluate_facts(&facts).expect("eval");
        assert_eq!(
            r.decision,
            Decision::ApprovalRequired,
            "an approval overlay is the only thing between this caller and the resource",
        );
        assert!(
            r.policy_ids.iter().any(|id| id == "approval-resource"),
            "the overlay that imposed the gate must be recorded; got {:?}",
            r.policy_ids,
        );
    }

    // Verdict parity: a high-risk call (which always CARRIES a step-up
    // required_scope) whose only Cedar gate is the approval overlay must
    // report ApprovalRequired, never a step-up Cedar did not declare —
    // even when the caller lacks the scope.
    #[test]
    fn approval_only_gate_on_a_high_risk_call_never_invents_step_up() {
        const APPROVAL_OVERLAY_ONLY: &str = r#"
            @id("role-allow")
            permit (
                principal in Group::"mcp-users",
                action == Action::"CallTool",
                resource
            );
            @id("codemode-mutation-approval")
            forbid (
                principal,
                action == Action::"CallTool",
                resource is Tool
            ) when {
                context.channel == "codemode" &&
                resource.side_effects &&
                !context.approval_present
            };
        "#;
        let eng = CedarEngine::from_source(APPROVAL_OVERLAY_ONLY).expect("parse");
        let mut facts = facts_from(
            &alice(&["mcp-users"]),
            &Action::CallTool {
                name: "example-messages.messages.send".into(),
                risk: RiskTier::High,
            },
            &high_tool(),
        );
        facts.context.channel = waygate_core::InvocationChannelFact::CodeMode;
        let r = eng.evaluate_facts(&facts).expect("eval");
        assert_eq!(
            r.decision,
            Decision::ApprovalRequired,
            "the only declared gate is the approval overlay; no step-up may be invented",
        );
    }

    // The narrowing-only invariant: a permit conditioned on the approval
    // context must never let a grant CREATE authorization. A set whose only
    // path to Allow is an approval-conditioned permit keeps the flat Deny —
    // with and without an unrelated forbid firing on the first pass.
    #[test]
    fn an_approval_conditioned_permit_never_infers_approval() {
        const APPROVAL_PERMIT_ONLY: &str = r#"
            @id("grant-becomes-authorization")
            permit (
                principal,
                action == Action::"CallTool",
                resource
            ) when { context.approval_present };
        "#;
        let eng = CedarEngine::from_source(APPROVAL_PERMIT_ONLY).expect("parse");
        let r = eng
            .evaluate_facts(&codemode_call_facts(&["mcp-users"], true))
            .expect("eval");
        assert_eq!(
            r.decision,
            Decision::Deny,
            "a baseline deny must never flip to ApprovalRequired via an approval-conditioned permit",
        );

        const APPROVAL_PERMIT_PLUS_FORBID: &str = r#"
            @id("grant-becomes-authorization")
            permit (
                principal,
                action == Action::"CallTool",
                resource
            ) when { context.approval_present };
            @id("codemode-mutation-approval")
            forbid (
                principal,
                action == Action::"CallTool",
                resource is Tool
            ) when {
                context.channel == "codemode" &&
                resource.side_effects &&
                !context.approval_present
            };
        "#;
        let eng = CedarEngine::from_source(APPROVAL_PERMIT_PLUS_FORBID).expect("parse");
        let r = eng
            .evaluate_facts(&codemode_call_facts(&["mcp-users"], true))
            .expect("eval");
        assert_eq!(
            r.decision,
            Decision::Deny,
            "a fired forbid must not launder an approval-conditioned permit into ApprovalRequired",
        );
    }

    // A non-approval forbid that also fires keeps the flat deny: the
    // re-eval with `approval_present` flipped still denies, so a hard
    // operator forbid is not bypassable by the approval path.
    #[test]
    fn a_hard_forbid_alongside_the_overlay_stays_a_flat_deny() {
        const OVERLAY_PLUS_HARD_FORBID: &str = r#"
            permit (principal in Group::"mcp-users", action, resource);
            forbid (
                principal,
                action == Action::"CallTool",
                resource is Tool
            ) when {
                context.channel == "codemode" &&
                resource.side_effects &&
                !context.approval_present
            };
            @id("hard-forbid-send")
            forbid (
                principal,
                action == Action::"CallTool",
                resource is Tool
            ) when { resource.name == "send_msg" };
        "#;
        let eng = CedarEngine::from_source(OVERLAY_PLUS_HARD_FORBID).expect("parse");
        let r = eng
            .evaluate_facts(&codemode_call_facts(&["mcp-users"], true))
            .expect("eval");
        assert_eq!(r.decision, Decision::Deny);
        assert!(
            r.policy_ids.iter().any(|id| id == "hard-forbid-send"),
            "the hard forbid remains determinative: {:?}",
            r.policy_ids,
        );
    }
}
