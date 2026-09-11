//! Policy tests as publish gates.
//!
//! An operator attaches assertions to a policy draft — "principal in group X
//! calling high-risk tool Y must be DENIED". When the draft is published, those
//! assertions run against the draft's Cedar content BEFORE it is mirrored to
//! `policies/*.cedar`. If any fails, the publish is REJECTED and the prior
//! published set stays untouched — exactly mirroring the load-time invariant a
//! broken `.cedar` already enforces (keep the previous set, never lock the
//! operator out).
//!
//! The typed test-case shapes live HERE (waygate-admin), not in the
//! dependency-light `waygate-policy` store crate: the store round-trips the
//! reserved `tests JSONB` column as opaque `serde_json::Value` and stays
//! content-agnostic, while the gate (which already owns the Cedar evaluator via
//! `waygate_authz`) deserializes and runs them. A draft staged with a malformed
//! test blob therefore fails CLOSED at the gate — it is rejected, never run as
//! "no tests".
//!
//! The runner reuses the live simulator's plumbing: `simulate_request_to_inputs`
//! turns a stored `SimulateRequest` into the `(Principal, Action, ResourceSpec)`
//! triple `CedarEngine::evaluate` takes, and `build_trace` produces the same
//! structured "why" the dashboard already renders, so a failing assertion shows
//! the operator the fired policies.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use waygate_authz::{CedarEngine, Decision};

use crate::policies::{build_trace, SimTraceEntry, SimulateRequest};

/// One assertion attached to a policy draft: run `request` through the draft's
/// Cedar content and require the verdict to match `expect`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyTestCase {
    /// Operator-facing label, surfaced verbatim in a failure summary.
    pub name: String,
    /// The hypothetical authorization request — same wire shape as
    /// `POST /api/v1/policies/simulate`.
    pub request: SimulateRequest,
    /// The decision (and optional reason / policy-id substrings) the request
    /// must produce under the draft.
    pub expect: ExpectedVerdict,
}

/// The expected outcome of a [`PolicyTestCase`]. `decision` is required; the two
/// `*_contains` fields are optional extra constraints — when set, the actual
/// result's reasons / policy-ids must contain the substring, letting an operator
/// pin not just "deny" but "denied by THIS overlay / for THIS reason".
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExpectedVerdict {
    pub decision: ExpectedDecision,
    /// When set, some human-readable `reason` on the result must contain this
    /// substring.
    #[serde(default)]
    pub reason_contains: Option<String>,
    /// When set, some fired `policy_id` must contain this substring.
    #[serde(default)]
    pub policy_id_contains: Option<String>,
}

/// The verdict a [`PolicyTestCase`] asserts. Maps 1:1 onto
/// [`waygate_authz::Decision`]; serialized as `allow` / `deny` / `step_up` to
/// match the simulator's wire vocabulary.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedDecision {
    Allow,
    Deny,
    StepUp,
    ApprovalRequired,
}

impl ExpectedDecision {
    /// The wire string for this expected decision, matching the simulator's
    /// `SimulateResponse::decision` vocabulary.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::StepUp => "step_up",
            Self::ApprovalRequired => "approval_required",
        }
    }

    /// Whether an engine `Decision` satisfies this expectation.
    fn matches(self, actual: Decision) -> bool {
        matches!(
            (self, actual),
            (Self::Allow, Decision::Allow)
                | (Self::Deny, Decision::Deny)
                | (Self::StepUp, Decision::StepUpRequired)
                // The approval overlay narrows an allow behind a grant; a
                // test asserting "deny" correctly fails on it (the call can
                // proceed with approval), so it needs no expectation of its
                // own beyond the wire string below.
                | (Self::ApprovalRequired, Decision::ApprovalRequired)
        )
    }
}

/// The wire string for an engine `Decision` (the same mapping the simulator
/// uses, so a `PolicyTestResult.actual` reads identically to a simulate response).
fn decision_str(d: Decision) -> &'static str {
    match d {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
        Decision::StepUpRequired => "step_up",
        Decision::ApprovalRequired => "approval_required",
    }
}

/// One case's outcome.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, schemars::JsonSchema)]
pub struct PolicyTestResult {
    pub name: String,
    /// The asserted decision.
    pub expected: ExpectedDecision,
    /// The decision the draft actually produced (`allow` / `deny` / `step_up`),
    /// or a sentinel when the draft could not be evaluated.
    pub actual: String,
    pub passed: bool,
    /// Why a case failed (decision mismatch, missing reason/policy-id substring,
    /// or a non-parsing draft). `None` on a pass.
    #[serde(default)]
    pub detail: Option<String>,
    /// The fired-policy trace for a FAILING case, so an operator sees which
    /// policies decided the (wrong) outcome. `None` on a pass or when the draft
    /// didn't parse (no engine to trace against).
    #[serde(default)]
    pub trace: Option<Vec<SimTraceEntry>>,
}

/// The aggregate report for a draft's attached tests.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, schemars::JsonSchema)]
pub struct PolicyTestReport {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    /// True iff every case passed. The publish gate keys on this.
    pub all_passed: bool,
    pub results: Vec<PolicyTestResult>,
}

/// Run `cases` against `content` (the draft's Cedar source) and report.
///
/// Parse handling: if `content` does not parse as a Cedar policy set, EVERY case
/// is reported `passed = false` with a "bundle does not parse as Cedar" detail
/// (and no trace — there's no engine to trace against). This guarantees a
/// non-parsing draft can never slip the publish gate as "all_passed" — the gate
/// keys on `all_passed`, which is false here. (`create_draft` already rejects
/// unparseable Cedar up front, so this is the belt-and-suspenders path for a
/// draft whose tests outlived a hypothetical future content edit.)
///
/// An empty `cases` slice yields an all-passed report with `total = 0` — a draft
/// with no attached assertions imposes no gate. (The publish gate only runs the
/// runner when the draft carries a NON-empty test set, so it never blocks on
/// `total = 0`; running it here on an empty slice is still well-defined.)
/// Evaluates each case under `tenant` — the tenant whose bundle is being
/// published/previewed. Cedar policies can branch on `principal.tenant` (e.g.
/// per-tenant overlays), so the gate MUST evaluate in the bundle's own tenant
/// context, not the converter's default stamp — exactly like the live
/// `/policies/simulate` handler overrides the tenant. Evaluating under the
/// wrong tenant would let a non-default-tenant draft pass or fail its publish
/// tests against the default tenant's authorization context.
pub(crate) fn run_policy_tests(
    content: &str,
    cases: &[PolicyTestCase],
    tenant: &waygate_core::TenantId,
) -> PolicyTestReport {
    let engine = match CedarEngine::from_source(content) {
        Ok(e) => e,
        Err(e) => {
            // Fail closed: report every case as failed so the gate blocks and the
            // operator sees the parse error against each assertion.
            let detail = format!("bundle does not parse as Cedar: {e}");
            let results: Vec<PolicyTestResult> = cases
                .iter()
                .map(|c| PolicyTestResult {
                    name: c.name.clone(),
                    expected: c.expect.decision,
                    actual: "error".to_owned(),
                    passed: false,
                    detail: Some(detail.clone()),
                    trace: None,
                })
                .collect();
            let failed = results.len();
            return PolicyTestReport {
                total: failed,
                passed: 0,
                failed,
                all_passed: failed == 0,
                results,
            };
        }
    };

    let snapshots = engine.list_policies();
    let mut results = Vec::with_capacity(cases.len());
    let mut passed = 0usize;
    for case in cases {
        // Evaluate in the bundle's tenant context — the facts builder stamps
        // it, mirroring the live simulator — and with the case's simulated
        // runtime context (channel / approval presence), so a test can pin an
        // approval overlay's behavior on the codemode channel.
        let facts =
            crate::policies::simulate_request_to_facts(case.request.clone(), tenant.clone());
        // STRICT evaluation: a request-time Cedar error (a policy referencing an
        // undefined attribute, a type mismatch) becomes an `Err` and FAILS the
        // case, rather than the lenient `evaluate` path which logs-and-ignores
        // the error and evaluates against a degraded result. A gate must
        // distinguish "policy denies it" from "the draft is BROKEN at eval time"
        // — a broken draft must never pass a test.
        let result = match engine.evaluate_facts_strict(&facts) {
            Ok(r) => r,
            Err(e) => {
                results.push(PolicyTestResult {
                    name: case.name.clone(),
                    expected: case.expect.decision,
                    actual: "error".to_owned(),
                    passed: false,
                    detail: Some(format!("cedar evaluator failed: {e}")),
                    trace: None,
                });
                continue;
            }
        };

        let actual = result.decision;
        let mut failures: Vec<String> = Vec::new();
        if !case.expect.decision.matches(actual) {
            failures.push(format!(
                "expected {}, got {}",
                case.expect.decision.as_str(),
                decision_str(actual),
            ));
        }
        if let Some(needle) = &case.expect.reason_contains {
            if !result.reasons.iter().any(|r| r.contains(needle)) {
                failures.push(format!("no reason contains {needle:?}"));
            }
        }
        if let Some(needle) = &case.expect.policy_id_contains {
            if !result.policy_ids.iter().any(|p| p.contains(needle)) {
                failures.push(format!("no fired policy id contains {needle:?}"));
            }
        }

        let case_passed = failures.is_empty();
        if case_passed {
            passed += 1;
        }
        // Attach the fired-policy trace ONLY on a failure (the "why" an operator
        // needs); a passing case needs no explanation.
        let trace = if case_passed {
            None
        } else {
            let (entries, _determinative) = build_trace(&result, &snapshots);
            Some(entries)
        };
        results.push(PolicyTestResult {
            name: case.name.clone(),
            expected: case.expect.decision,
            actual: decision_str(actual).to_owned(),
            passed: case_passed,
            detail: (!case_passed).then(|| failures.join("; ")),
            trace,
        });
    }

    let total = results.len();
    let failed = total - passed;
    PolicyTestReport {
        total,
        passed,
        failed,
        all_passed: failed == 0,
        results,
    }
}

/// A short, operator-facing one-line summary of a FAILED report, for the publish
/// gate's 4xx message. Names the first few failing cases.
pub(crate) fn failure_summary(report: &PolicyTestReport) -> String {
    let failing: Vec<String> = report
        .results
        .iter()
        .filter(|r| !r.passed)
        .map(|r| {
            let detail = r.detail.as_deref().unwrap_or("failed");
            format!("`{}`: {detail}", r.name)
        })
        .collect();
    // Cap the inline list so a draft with many failing cases doesn't produce a
    // multi-kilobyte error body; the run_tests endpoint returns the full report.
    let shown: Vec<String> = failing.iter().take(5).cloned().collect();
    let suffix = if failing.len() > shown.len() {
        format!(" (+{} more)", failing.len() - shown.len())
    } else {
        String::new()
    };
    format!(
        "policy tests failed: {} of {} — {}{}",
        report.failed,
        report.total,
        shown.join("; "),
        suffix,
    )
}

/// Run a bundle's attached policy tests as the PUBLISH GATE — the single choke
/// point every publish surface calls (the REST / dashboard / propose
/// `publish_bundle_core`, and the tenant-creation clone-from-default), so the
/// gate cannot be bypassed by adding a new publish path. Evaluates under
/// `tenant` (the bundle's own tenant) and fails CLOSED: returns `Ok(())` when
/// the bundle has no attached tests or every assertion passes, and `Err(reason)`
/// when the stored tests blob is malformed (can't be evaluated) or any assertion
/// fails. The `reason` is the operator-facing string to surface in the rejection
/// and the `Denied` publish-audit row.
pub(crate) fn evaluate_publish_gate(
    content: &str,
    tests_json: Option<&serde_json::Value>,
    tenant: &waygate_core::TenantId,
) -> Result<(), String> {
    let Some(v) = tests_json else {
        return Ok(());
    };
    let cases: Vec<PolicyTestCase> = serde_json::from_value(v.clone()).map_err(|e| {
        format!("stored policy tests are malformed and cannot be evaluated; publish refused: {e}")
    })?;
    if cases.is_empty() {
        return Ok(());
    }
    let report = run_policy_tests(content, &cases, tenant);
    if report.all_passed {
        Ok(())
    } else {
        Err(failure_summary(&report))
    }
}

// Re-export the converter so the runner doesn't reach across modules in two
// places; keeps the `use` list above tidy.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policies::{SimulateAction, SimulatePrincipal, SimulateRequest, SimulateResource};
    use waygate_mcp::protocol::RiskTier;

    /// A draft that permits everything (no forbids) — every request allows.
    const PERMIT_ALL: &str = "@id(\"permit-all\")\npermit(principal, action, resource);";

    /// A draft that permits everything but FORBIDS calling a high-risk tool,
    /// with annotations so reason/policy-id assertions have something to match.
    /// Mirrors the proven `resource.risk == "..."` shape used by the engine's
    /// own `ADMIN_POLICY` tests — a `CallTool` always carries a `Tool` resource
    /// with a `risk` attribute, so no `has`/`is` guard is needed.
    const FORBID_HIGH_CALL: &str = "@id(\"baseline-permit\")\n\
         permit(principal, action, resource);\n\
         @id(\"forbid-high-call\")\n\
         @reason(\"high-risk tool calls are forbidden in this draft\")\n\
         forbid(\n\
             principal,\n\
             action == Action::\"CallTool\",\n\
             resource\n\
         )\n\
         when { resource.risk == \"high\" };";

    fn call_high_request(sub: &str) -> SimulateRequest {
        SimulateRequest {
            principal: SimulatePrincipal {
                sub: sub.to_owned(),
                email: None,
                groups: vec![],
                issuer: "simulation".into(),
                scopes: vec![],
                auth_method: Default::default(),
                scim: None,
                roles: vec![],
            },
            action: SimulateAction::CallTool {
                name: "wire_money".into(),
                risk: RiskTier::High,
            },
            resource: SimulateResource::Tool {
                operation: None,
                server: "bank".into(),
                name: "wire_money".into(),
                risk: RiskTier::High,
                side_effects: true,
                pii: false,
            },
            context: Default::default(),
        }
    }

    fn case(name: &str, request: SimulateRequest, expect: ExpectedVerdict) -> PolicyTestCase {
        PolicyTestCase {
            name: name.to_owned(),
            request,
            expect,
        }
    }

    fn expect(decision: ExpectedDecision) -> ExpectedVerdict {
        ExpectedVerdict {
            decision,
            reason_contains: None,
            policy_id_contains: None,
        }
    }

    /// A test case carrying the codemode channel exercises an approval
    /// overlay end to end: the case expects `approval_required` on the
    /// codemode channel while the identical direct-channel case stays
    /// `allow` — pinning that the runner threads the simulated context
    /// into the evaluation instead of defaulting every case to direct.
    #[test]
    fn codemode_channel_case_exercises_an_approval_overlay() {
        const PERMIT_PLUS_OVERLAY: &str = "@id(\"permit-all\")\n\
             permit(principal, action, resource);\n\
             @id(\"codemode-mutation-approval\")\n\
             forbid(principal, action == Action::\"CallTool\", resource)\n\
             when { context.channel == \"codemode\" &&\n\
                    resource.side_effects &&\n\
                    !context.approval_present };";
        let mut codemode = call_high_request("alice");
        codemode.context.channel = crate::policies::SimulateChannel::CodeMode;
        // High-risk calls step up before approval; carry the scope so the
        // approval overlay is the only gate this case exercises.
        codemode.principal.scopes = vec!["mcp:invoke:high".to_owned()];
        let cases = vec![
            case(
                "codemode effect is approval-gated",
                codemode,
                ExpectedVerdict {
                    decision: ExpectedDecision::ApprovalRequired,
                    reason_contains: None,
                    policy_id_contains: Some("codemode-mutation-approval".to_owned()),
                },
            ),
            case(
                "direct effect is untouched by the overlay",
                call_high_request("alice"),
                expect(ExpectedDecision::Allow),
            ),
        ];
        let report = run_policy_tests(
            PERMIT_PLUS_OVERLAY,
            &cases,
            &waygate_core::TenantId::default_id(),
        );
        assert!(report.all_passed, "results: {:?}", report.results);
        assert_eq!(report.results[0].actual, "approval_required");
        assert_eq!(report.results[1].actual, "allow");
    }

    #[test]
    fn passing_case_reports_all_passed() {
        // permit-all + expect allow ⇒ pass.
        let cases = vec![case(
            "allows the call",
            call_high_request("alice"),
            expect(ExpectedDecision::Allow),
        )];
        let report = run_policy_tests(PERMIT_ALL, &cases, &waygate_core::TenantId::default_id());
        assert_eq!(report.total, 1);
        assert_eq!(report.passed, 1);
        assert_eq!(report.failed, 0);
        assert!(report.all_passed);
        assert!(report.results[0].passed);
        assert!(report.results[0].detail.is_none());
        assert!(
            report.results[0].trace.is_none(),
            "a passing case carries no trace",
        );
        assert_eq!(report.results[0].actual, "allow");
    }

    #[test]
    fn failing_case_expected_deny_but_policy_allows() {
        // The headline gate case: the operator asserts the high-risk call is
        // DENIED, but the draft permits it. The runner must report the mismatch
        // (so the publish gate blocks) and attach a trace.
        let cases = vec![case(
            "high-risk call must be denied",
            call_high_request("mallory"),
            expect(ExpectedDecision::Deny),
        )];
        let report = run_policy_tests(PERMIT_ALL, &cases, &waygate_core::TenantId::default_id());
        assert!(!report.all_passed, "a mismatch must block the gate");
        assert_eq!(report.failed, 1);
        let r = &report.results[0];
        assert!(!r.passed);
        assert_eq!(r.expected, ExpectedDecision::Deny);
        assert_eq!(r.actual, "allow");
        let detail = r.detail.as_deref().unwrap();
        assert!(
            detail.contains("expected deny") && detail.contains("got allow"),
            "detail must explain the mismatch: {detail}",
        );
        assert!(
            r.trace.is_some(),
            "a failing case must carry the fired-policy trace",
        );
    }

    #[test]
    fn deny_case_passes_against_a_forbidding_draft() {
        // Same assertion (high call must be denied), but now the draft DOES
        // forbid it ⇒ the case passes.
        let cases = vec![case(
            "high-risk call must be denied",
            call_high_request("mallory"),
            expect(ExpectedDecision::Deny),
        )];
        let report = run_policy_tests(
            FORBID_HIGH_CALL,
            &cases,
            &waygate_core::TenantId::default_id(),
        );
        assert!(report.all_passed, "the forbid satisfies the deny assertion");
        assert_eq!(report.results[0].actual, "deny");
    }

    #[test]
    fn reason_contains_hit_and_miss() {
        // Hit: the forbid carries the matching @reason annotation.
        let hit = vec![case(
            "denied for the right reason",
            call_high_request("mallory"),
            ExpectedVerdict {
                decision: ExpectedDecision::Deny,
                reason_contains: Some("forbidden in this draft".into()),
                policy_id_contains: None,
            },
        )];
        let report = run_policy_tests(
            FORBID_HIGH_CALL,
            &hit,
            &waygate_core::TenantId::default_id(),
        );
        assert!(report.all_passed, "the reason substring is present");

        // Miss: the substring is absent ⇒ the case fails even though the
        // decision matched.
        let miss = vec![case(
            "wrong reason text",
            call_high_request("mallory"),
            ExpectedVerdict {
                decision: ExpectedDecision::Deny,
                reason_contains: Some("this text is not in any reason".into()),
                policy_id_contains: None,
            },
        )];
        let report = run_policy_tests(
            FORBID_HIGH_CALL,
            &miss,
            &waygate_core::TenantId::default_id(),
        );
        assert!(
            !report.all_passed,
            "a missing reason substring fails the case"
        );
        let detail = report.results[0].detail.as_deref().unwrap();
        assert!(detail.contains("no reason contains"), "detail: {detail}");
    }

    #[test]
    fn policy_id_contains_hit_and_miss() {
        // Hit: the forbid's @id is "forbid-high-call".
        let hit = vec![case(
            "denied by the expected policy",
            call_high_request("mallory"),
            ExpectedVerdict {
                decision: ExpectedDecision::Deny,
                reason_contains: None,
                policy_id_contains: Some("forbid-high-call".into()),
            },
        )];
        let report = run_policy_tests(
            FORBID_HIGH_CALL,
            &hit,
            &waygate_core::TenantId::default_id(),
        );
        assert!(report.all_passed, "the fired policy id matches");

        // Miss: no fired policy id contains this substring.
        let miss = vec![case(
            "wrong policy id",
            call_high_request("mallory"),
            ExpectedVerdict {
                decision: ExpectedDecision::Deny,
                reason_contains: None,
                policy_id_contains: Some("some-other-policy".into()),
            },
        )];
        let report = run_policy_tests(
            FORBID_HIGH_CALL,
            &miss,
            &waygate_core::TenantId::default_id(),
        );
        assert!(!report.all_passed, "a missing policy-id substring fails");
        let detail = report.results[0].detail.as_deref().unwrap();
        assert!(
            detail.contains("no fired policy id contains"),
            "detail: {detail}",
        );
    }

    #[test]
    fn non_parsing_content_blocks_every_case() {
        // A draft that doesn't parse must fail closed: every case fails, the
        // report is not all_passed, and the detail names the parse failure.
        let cases = vec![
            case(
                "anything",
                call_high_request("alice"),
                expect(ExpectedDecision::Allow),
            ),
            case(
                "anything else",
                call_high_request("bob"),
                expect(ExpectedDecision::Deny),
            ),
        ];
        let report = run_policy_tests(
            "this is not valid cedar {{{",
            &cases,
            &waygate_core::TenantId::default_id(),
        );
        assert!(
            !report.all_passed,
            "a non-parsing draft must never pass the gate",
        );
        assert_eq!(report.failed, 2);
        assert_eq!(report.passed, 0);
        for r in &report.results {
            assert!(!r.passed);
            assert_eq!(r.actual, "error");
            assert!(
                r.detail.as_deref().unwrap().contains("does not parse"),
                "detail must name the parse failure",
            );
        }
    }

    #[test]
    fn empty_cases_is_a_vacuous_pass() {
        // No attached assertions ⇒ all_passed with total 0 (the gate imposes no
        // constraint, matching "a draft with no tests publishes freely").
        let report = run_policy_tests(PERMIT_ALL, &[], &waygate_core::TenantId::default_id());
        assert_eq!(report.total, 0);
        assert!(report.all_passed);
        assert!(report.results.is_empty());
    }

    #[test]
    fn evaluates_under_the_passed_tenant_not_the_default() {
        // The runner must evaluate each case under the
        // BUNDLE's tenant, not the converter's default stamp — Cedar policies
        // can branch on `principal.tenant`. This draft forbids the call ONLY for
        // tenant "acme"; the SAME request+assertion must therefore fail under
        // `default` (permitted there) and pass under `acme` (forbidden there).
        // If the runner ignored the passed tenant (the bug), the acme run would
        // evaluate under `default` and the assertion would wrongly fail.
        const TENANT_FORBID: &str = "permit(principal, action, resource);\n\
            forbid(principal, action, resource) when { principal.tenant == \"acme\" };";
        let cases = vec![case(
            "high-risk call denied for acme",
            call_high_request("alice"),
            expect(ExpectedDecision::Deny),
        )];

        let under_default =
            run_policy_tests(TENANT_FORBID, &cases, &waygate_core::TenantId::default_id());
        assert!(
            !under_default.all_passed,
            "under the default tenant the forbid doesn't fire, so the expect-deny \
             assertion must fail (the call is permitted)",
        );

        let acme = waygate_core::TenantId::parse("acme").expect("valid tenant id");
        let under_acme = run_policy_tests(TENANT_FORBID, &cases, &acme);
        assert!(
            under_acme.all_passed,
            "under tenant acme the forbid fires, so the expect-deny assertion passes \
             — proving the runner honours the passed tenant, not the default stamp",
        );
    }

    #[test]
    fn a_draft_broken_at_eval_time_fails_closed_not_silently_evaluated() {
        // STRICT evaluation. A draft that PARSES but errors at
        // EVAL time (a policy referencing an undefined attribute) must FAIL its
        // tests, not be silently evaluated against a degraded result. The first
        // permit allows the call — so a LENIENT eval would log+ignore the second
        // policy's error and let an `expect allow` case PASS — but the second
        // policy reads an undefined attribute, which strict eval surfaces as an
        // evaluator error that fails the case, so the gate blocks the broken
        // draft.
        const BROKEN_AT_EVAL: &str = "permit(principal, action, resource);\n\
            permit(principal, action, resource) when { principal.no_such_attr == \"x\" };";
        let cases = vec![case(
            "the call is allowed",
            call_high_request("alice"),
            expect(ExpectedDecision::Allow),
        )];
        let report = run_policy_tests(
            BROKEN_AT_EVAL,
            &cases,
            &waygate_core::TenantId::default_id(),
        );
        assert!(
            !report.all_passed,
            "a draft that errors at eval time must fail the gate, not pass on a lenient eval",
        );
        assert_eq!(report.results[0].actual, "error");
        assert!(
            report.results[0]
                .detail
                .as_deref()
                .unwrap_or("")
                .contains("evaluator failed"),
            "the failure must name the evaluator error; got {:?}",
            report.results[0].detail,
        );
    }

    #[test]
    fn evaluate_publish_gate_is_the_shared_choke_point() {
        // The choke point every publish surface (REST/dashboard/propose +
        // tenant-creation) calls. Covers its four outcomes so the seed-bundle
        // path and the API path share one tested gate.
        let tenant = waygate_core::TenantId::default_id();
        // No attached tests ⇒ Ok (a bundle without tests publishes freely).
        assert!(evaluate_publish_gate(PERMIT_ALL, None, &tenant).is_ok());
        // Passing tests ⇒ Ok.
        let pass = serde_json::to_value(vec![case(
            "allowed",
            call_high_request("a"),
            expect(ExpectedDecision::Allow),
        )])
        .unwrap();
        assert!(evaluate_publish_gate(PERMIT_ALL, Some(&pass), &tenant).is_ok());
        // Failing tests ⇒ Err(summary).
        let fail = serde_json::to_value(vec![case(
            "must deny",
            call_high_request("a"),
            expect(ExpectedDecision::Deny),
        )])
        .unwrap();
        let err = evaluate_publish_gate(PERMIT_ALL, Some(&fail), &tenant).unwrap_err();
        assert!(err.contains("policy tests failed"), "summary: {err}");
        // Malformed blob ⇒ Err (fail closed), never a panic.
        let bad = serde_json::json!({"garbage": true});
        let err = evaluate_publish_gate(PERMIT_ALL, Some(&bad), &tenant).unwrap_err();
        assert!(err.contains("malformed"), "summary: {err}");
    }

    #[test]
    fn failure_summary_names_the_failing_case() {
        let cases = vec![case(
            "high-risk call must be denied",
            call_high_request("mallory"),
            expect(ExpectedDecision::Deny),
        )];
        let report = run_policy_tests(PERMIT_ALL, &cases, &waygate_core::TenantId::default_id());
        let summary = failure_summary(&report);
        assert!(summary.contains("1 of 1"), "summary: {summary}");
        assert!(
            summary.contains("high-risk call must be denied"),
            "summary must name the failing case: {summary}",
        );
    }
}
