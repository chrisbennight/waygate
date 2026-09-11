//! Stage 8 of the invocation pipeline — the approval-grant gate, split out
//! of the orchestrator module. A live per-call grant is required when either
//! authority demands it: the catalog's per-tool `requires_approval` flag (a
//! floor applying to every dispatch) or a Cedar `ApprovalRequired` verdict
//! from the authorize stage (the operator's channel- and context-aware
//! policy lever). Refusals fail closed as
//! [`InvocationError::ApprovalRequired`].

use waygate_invocation::InvocationError;

use crate::audit::AuditOutcome;
use crate::catalog::ResolutionAuthority;

use super::{decision_inputs, DefaultInvocationService, InvocationContext};

impl DefaultInvocationService {
    /// Stage 8 — HITL approval-grant gate.
    ///
    /// When the admitted tool has `requires_approval=true`, atomically claim a matching live
    /// grant (`principal × tool × argument_hash × time window`,
    /// optionally client-scoped). On no match: return
    /// [`InvocationError::ApprovalRequired`] and the adapter
    /// surfaces a structured MCP error so the client can run the
    /// human-in-the-loop UX (request approval, wait, retry).
    ///
    /// The claim is one-time (sets `consumed_at = now()` atomically
    /// via `UPDATE ... FOR UPDATE SKIP LOCKED RETURNING`), so two
    /// concurrent dispatches can't replay the same approval and the
    /// operator-issued grant matches the call shape they vetted.
    ///
    /// No-ops when `requires_approval=false` AND
    /// `requires_approval_known=true`
    ///    (the steady state for almost every tool — operators flip
    ///    it on per-tool in admin UI; trusted catalog source says no
    ///    HITL). This includes a manifest fallback whose approval
    ///    requirements are known.
    ///
    /// Anonymous calls (no principal) under a HITL-needing tool
    /// refuse — there's no `principal_sub` to bind a grant to.
    /// Auth-disabled dev mode keeps working for non-HITL tools;
    /// real deployments will have already 401'd at the bearer layer
    /// before reaching this stage.
    ///
    /// Fail-closed branches (refuse with `ApprovalRequired`):
    /// - Approval is required but no grant store is wired.
    /// - Stage 1 admitted a manifest fallback whose approval requirements are
    ///   unknown or whose required grant has no authoritative catalog tool ID.
    /// - `claim_grant` returns `Err` (catalog unavailable on the
    ///   atomic-claim path).
    /// - `claim_grant` returns `None` (no matching live grant, or
    ///   already consumed).
    pub(super) async fn check_approval(
        &self,
        ctx: &mut InvocationContext<'_>,
    ) -> Result<(), InvocationError> {
        let result = self.check_approval_inner(ctx).await;
        if let Err(InvocationError::ApprovalRequired { reason, .. }) = &result {
            let facts = ctx.facts();
            let (scopes, auth_method, roles, side_effects) = decision_inputs(ctx.principal, facts);
            // The reason names which authority demanded the grant. The
            // distinction is load-bearing for decision-impact replay:
            // Cedar's verdict for a policy-gated refusal was
            // ApprovalRequired, while for a catalog-flag-only refusal it
            // was Allow — replaying either as a policy deny would
            // fabricate transitions under an unchanged bundle.
            let authority_label = if ctx.cedar_approval_policies.is_some() {
                "approval required by policy"
            } else {
                "approval required"
            };
            self.audit
                .record_chained_best_effort(
                    ctx.audit_event("CallTool", AuditOutcome::Denied)
                        .with_category(ctx.audit_category)
                        .with_principal(ctx.principal)
                        .with_tool(ctx.server, ctx.tool)
                        .with_risk(facts.risk)
                        .with_pii(facts.pii)
                        .with_policies(ctx.authz_policy_ids.clone())
                        .with_decision_inputs(scopes, auth_method, roles, side_effects)
                        .with_reason(format!("{authority_label}: {reason}")),
                )
                .await;
        }
        result
    }

    async fn check_approval_inner(
        &self,
        ctx: &mut InvocationContext<'_>,
    ) -> Result<(), InvocationError> {
        let facts = ctx.facts();
        if matches!(
            ctx.tool_snapshot().authority(),
            ResolutionAuthority::ManifestFallback {
                approval_requirements_known: false,
                ..
            }
        ) {
            waygate_telemetry::metrics::record_invocation_approval_unknown_refusal();
            tracing::error!(
                server = %ctx.server,
                tool = %ctx.tool,
                "HITL approval authority is unknown; refusing dispatch",
            );
            return Err(InvocationError::ApprovalRequired {
                tool: format!("{}.{}", ctx.server, ctx.tool),
                reason: "approval authority unavailable".into(),
                satisfiable: false,
            });
        }
        // A live grant is required when either authority demands it: the
        // catalog classification flag (a per-tool floor applying to every
        // dispatch) or a Cedar approval-overlay verdict from the authorize
        // stage (the operator's channel- and context-aware policy lever).
        if ctx.cedar_approval_policies.is_none()
            && facts.requires_approval_known
            && !facts.requires_approval
        {
            return Ok(());
        }
        let Some(principal) = ctx.principal else {
            // No principal to bind to — refuse rather than silently
            // dispatch a HITL-required tool against an anonymous
            // caller (which can only happen in auth-disabled dev
            // mode, but the fail-safe is the safer default).
            return Err(InvocationError::ApprovalRequired {
                tool: format!("{}.{}", ctx.server, ctx.tool),
                reason: "HITL approval requires an authenticated principal".into(),
                satisfiable: false,
            });
        };
        let fq = format!("{}.{}", ctx.server, ctx.tool);
        let tenant = principal.tenant.as_str();
        let Some(catalog_store) = self.catalog_store.as_ref() else {
            return Err(InvocationError::ApprovalRequired {
                tool: fq,
                reason: "approval store unavailable".into(),
                satisfiable: false,
            });
        };
        let (tool_id, tool_behavior_hash) = match ctx.tool_snapshot().authority() {
            ResolutionAuthority::Catalog {
                tool_id,
                schema_hash,
            } => (*tool_id, schema_hash.as_str()),
            ResolutionAuthority::ManifestFallback {
                approval_requirements_known,
                ..
            } => {
                tracing::error!(
                    user = %principal.sub,
                    server = %ctx.server,
                    tool = %ctx.tool,
                    approval_requirements_known,
                    "HITL approval lacks authoritative catalog identity; refusing dispatch",
                );
                return Err(InvocationError::ApprovalRequired {
                    tool: fq,
                    reason: if *approval_requirements_known {
                        "approval-required manifest tool has no authoritative catalog identity"
                            .into()
                    } else {
                        "approval authority unavailable".into()
                    },
                    satisfiable: false,
                });
            }
            ResolutionAuthority::SyntheticModel => {
                return Err(InvocationError::ApprovalRequired {
                    tool: fq,
                    reason: "synthetic model has no approval-grant identity".into(),
                    satisfiable: false,
                });
            }
        };
        // Hash the call's arguments using the same
        // canonical-JSON rule that grant-issuing admin endpoints use
        // so a grant for {to: "alice"} never matches
        // {to: "#general"} even when the JSON differs only by
        // whitespace or key order.
        let arg_hash = waygate_catalog::argument_hash(ctx.arguments.as_ref());
        let approval_binding =
            waygate_catalog::approval_binding_hash(tool_behavior_hash, &arg_hash);
        let lookup = waygate_catalog::GrantLookup {
            tenant_id: tenant,
            principal_sub: principal.sub.as_str(),
            principal_issuer: principal.issuer.as_str(),
            // Principal.client_id is not yet plumbed here;
            // for now every grant lookup is any-client (None). Grants
            // minted with a specific client_id still match via the
            // `client_id IS NULL OR client_id = $caller` predicate
            // (here $caller is NULL so they don't), so operators
            // can't yet write client-scoped grants — that capability
            // ships with the restructure.
            client_id: None,
            tool_id,
            // The behavior-bound approval hash (behavior version + canonical
            // arguments) AND the Code Mode execution binding both apply: a
            // grant must match the reviewed contract generation it was
            // approved against and, when Code Mode proposed it, the exact
            // execution that carried the proposal.
            argument_hash: approval_binding.as_str(),
            execution_binding: ctx.approval_binding.as_ref().map(|binding| {
                waygate_catalog::GrantExecutionBinding {
                    execution_id: binding.execution_id,
                    source_digest: binding.source_digest.as_str(),
                    call_id: binding.call_id,
                }
            }),
        };
        match catalog_store.claim_grant(lookup).await {
            Ok(Some(grant)) => {
                tracing::info!(
                    user = %principal.sub,
                    server = %ctx.server,
                    tool = %ctx.tool,
                    grant_id = %grant.id,
                    approver = %grant.approver,
                    "HITL grant claimed; dispatch proceeds",
                );
                // Mark the context when the grant satisfied a Cedar
                // approval verdict: the success row's reason then records
                // that this effect was policy-gated, which decision-impact
                // replay needs to reproduce the ApprovalRequired verdict
                // instead of fabricating an allow→approval_required
                // transition under an unchanged bundle.
                if ctx.cedar_approval_policies.is_some() {
                    ctx.policy_gated_grant_consumed = true;
                }
                Ok(())
            }
            Ok(None) => {
                tracing::info!(
                    user = %principal.sub,
                    server = %ctx.server,
                    tool = %ctx.tool,
                    "no HITL grant matched (or already consumed); refusing dispatch",
                );
                // Fan out the "needs approval" signal to
                // subscribed operators (WebSocket / future notifiers).
                // Best-effort — the denial path is unchanged regardless
                // of whether anyone receives the event.
                if let Some(notifier) = self.hitl_notifier.as_ref() {
                    notifier.notify_approval_needed(waygate_invocation::HitlApprovalNeeded {
                        tenant_id: tenant.to_owned(),
                        principal_sub: principal.sub.clone(),
                        principal_issuer: principal.issuer.clone(),
                        server: ctx.server.to_owned(),
                        tool: ctx.tool.to_owned(),
                        argument_hash: arg_hash.clone(),
                        behavior_hash: tool_behavior_hash.to_owned(),
                    });
                }
                Err(InvocationError::ApprovalRequired {
                    tool: fq,
                    reason: "tool requires human approval; no matching grant".into(),
                    // The one refusal a granted approval + identical retry
                    // can cure — adapters may project it into an interactive
                    // round trip.
                    satisfiable: true,
                })
            }
            Err(e) => {
                // Catalog-store error on the HITL path: fail closed
                // — refusing dispatch is the safe direction for a
                // requires_approval tool when we can't verify a
                // grant exists. The operator sees a structured
                // error and the underlying sqlx detail stays in
                // `tracing::error!` (not on the wire).
                tracing::error!(
                    user = %principal.sub,
                    server = %ctx.server,
                    tool = %ctx.tool,
                    error = %e,
                    "HITL claim_grant failed; refusing dispatch",
                );
                Err(InvocationError::ApprovalRequired {
                    tool: fq,
                    reason: "approval store unavailable".into(),
                    satisfiable: false,
                })
            }
        }
    }
}
