# Evidence caller classification

This document assigns every production `EvidenceRecorder` caller to one of the
three reliability postures. Choose
from the event's security and delivery contract, not from latency or test
convenience.

The inventory is anchored to producer symbols and event actions rather than line
numbers. Test recorders and recorder implementations are not callers and are
outside the inventory.

## Chained best effort

These events are security or compliance evidence whose absence must be visible,
but an evidence-store failure must not change the request's allow/deny/result.
They use `record_chained_best_effort`: successful rows join the tenant hash
chain, contention and known pre-commit failures are measured drops, and commit
uncertainty is measured as unknown. Hierarchy-bearing nested invocations also
enqueue configured external targets inside that bounded attempt so exporters
retain their parent/step/call/attempt relationship; direct events do not.

| Producer | Events covered | Reason |
|---|---|---|
| `DefaultInvocationService::resolve_tool` | catalog quarantine refusal | Governed dispatch refusal. |
| `DefaultInvocationService::authorize` | Cedar deny and step-up | Authorization decisions used for replay and compliance review. |
| `DefaultInvocationService::{check_quota,check_profile_restrictions}` | rate-limit and API-key-profile denials | Governed dispatch refusals. |
| `DefaultInvocationService::prepare_output_validation` | invalid approved output schema | Approved catalog state is unsafe to dispatch. |
| `DefaultInvocationService::check_approval` | every `ApprovalRequired` refusal | Human-approval enforcement decision. |
| `DefaultInvocationService::{validate_output,inspect_response,flush_redaction_audits}` | schema violation, inspection block, and redaction summaries | Response-integrity and DLP decisions. |
| `DefaultInvocationService::record_outcome` | tool-call success and upstream execution error | Final governed tool-call outcome. |
| `DefaultInvocationService::{record_llm_outcome,check_llm_budget}` and `finalize_stream_audit` | LLM final outcomes and budget denials, including stream close/drop | Final governed inference outcome. |
| `GatewayServer::authorize_builtin` | built-in deny, step-up, and indeterminate fail-closed refusal | Control-plane authorization decision. |
| `EvidenceAuthAttempts::record` | rejected bearer validation | Authentication security signal; bounded non-blocking submission keeps PostgreSQL latency and queue saturation off the response path without one detached task per rejection. |
| `waygate_as::audit::record`, the consent decision handler, and the admin OAuth session-revoke handler | OAuth token/callback/consent/revocation events | Authentication and delegated-authority evidence. |
| `UpstreamPool::emit_drift_audit` | schema or security-metadata drift and automatic quarantine | Catalog-integrity decision. |
| `ControlTools::quarantine_server` attribution | operator quarantine action | Supplementary chain-covered attribution after the catalog update; it must not turn a completed quarantine into an error. |
| policy-bundle publish gates, including tenant seed publication | blocked publish | Security validation refusal; the rejected operation has no mutation to roll back. |

## Required

These callers use `record_required` and fail closed when durable evidence
cannot be written.

| Producer group | Contract |
|---|---|
| `DefaultInvocationService::record_pre_call` | Side-effecting dispatch in fail-closed audit mode never reaches the upstream without durable evidence of intent. |
| break-glass gate and break-glass admin mint/revoke | Override use and lifecycle must be durable. |
| audit bundle signing, retention, routing, and explicit sweep handlers | Evidence-control mutations must audit atomically from the caller's perspective. |
| admin mutation helpers already wired for fail-closed evidence, OAuth consent revoke, upstream-session revoke, and HITL change-request propose/deny/execute-failure paths | The handler validates and writes required evidence as part of its fail-closed contract. |

## Unchained best effort

These callers use `record_best_effort`.

| Producer group | Contract |
|---|---|
| discovery auditing | Optional, high-volume operational visibility. |
| boot activation, fleet/reload notices, manifest/policy reload outcomes, and upstream reconnect health | Recovery and lifecycle telemetry must not wait on the per-tenant chain. |
| dashboard server recovery actions and MCP control-plane reconnect/reload attribution | Recovery actions must complete even when the audit database is degraded. |
| successful legacy policy/manifest bundle draft, publish, and rollback rows | They are emitted after mutation. Changing them to required at that point would fail the response after the irreversible write; moving required evidence before mutation needs a separate side-effect-ordering change. |
| API-key lifecycle and other legacy post-mutation admin rows | The supplementary evidence write follows the committed side effect; failure must not imply the action was undone. |
| one-time change-request secret retrieval | The secret is burned before the supplementary fingerprint-only event; an audit failure cannot make the caller lose the secret response. |

## Invariants

- No existing required caller is downgraded.
- Chained best effort never implies caller-visible failure. Only events carrying
  nested invocation hierarchy request configured outbox delivery.
- A security event is not classified as operational merely because it is
  frequent.
- A post-mutation audit is not changed to required until its evidence write can
  be ordered before the irreversible action.
- New or ambiguous callers require an explicit update to this classification.
