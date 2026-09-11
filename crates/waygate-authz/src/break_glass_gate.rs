//! [`BreakGlassGate`] — an [`AuthzGate`] decorator that
//! gives an operator-issued break-glass token the chance to
//! override a Cedar `Deny`.
//!
//! Wraps any inner gate (typically [`crate::CedarGate`]).
//! On `Allow` / `StepUpRequired` it passes through. On
//! `Deny` it:
//!
//! 1. Looks up usable tokens for `(tenant, sub, fq_tool)`
//!    in the [`BreakGlassStore`].
//! 2. Filters candidates by AMR satisfaction.
//! 3. Attempts the conditional single-use claim
//!    ([`BreakGlassStore::try_claim`]); the first claim
//!    that wins is the one applied.
//! 4. Emits a HIGH-VISIBILITY audit event
//!    (`BreakGlassUse`, `AdminMutation` category) naming
//!    the token id, the minting admin (`issued_by`), the
//!    minting reason, and the original Deny verdict so
//!    an after-action review reconstructs the override
//!    end-to-end from one row.
//! 5. Returns `AuthzVerdict::Allow`. The dispatch then
//!    proceeds as if the Cedar verdict had been Allow
//!    from the start.
//!
//! If no token applies / no claim succeeds, the original
//! `Deny` is returned unchanged — no silent fall-through.
//!
//! ## Why a wrapper (not a flag on CedarGate)
//!
//! - Keeps `CedarGate` zero-deps on Postgres (it stays a
//!   pure adapter to the policy engine).
//! - Lets the composition root decide whether to enable
//!   break-glass at all (no store wired ⇒ no wrapper ⇒
//!   no override path).
//! - The wrapper carries the [`SharedEvidence`] handle so
//!   the audit emission happens AT the override site
//!   (one source of truth for "this Deny was overridden
//!   at time T by token X"), not as a side-channel
//!   stamped onto an unrelated event later.
//!
//! ## Why no AMR enforcement yet
//!
//! `Principal` doesn't carry an `amr` field today. The
//! runtime gate accepts tokens whose `requires_amr` is
//! EMPTY; tokens with non-empty `requires_amr` will
//! eventually be enforceable once `PrincipalFacts.amr`
//! lands. Until then, the admin handler refuses to mint
//! non-empty `requires_amr` tokens, so operators can't be
//! misled into thinking MFA is enforced when it isn't.

use std::sync::Arc;

use async_trait::async_trait;

use waygate_mcp::audit::SharedEvidence;
use waygate_mcp::authz::{
    AuthzGate, AuthzVerdict, BuiltinAuthz, ProbeVerdict, SkillAccessFacts, ToolFacts,
};
use waygate_mcp::{AuditEvent, AuditOutcome, EvidenceCategory};
use waygate_oidc::Principal;
use waygate_telemetry::metrics::record_break_glass_use;

use crate::break_glass::{amr_subset_satisfied, scope_pattern_matches, SharedBreakGlassStore};

pub struct BreakGlassGate {
    inner: Arc<dyn AuthzGate>,
    store: SharedBreakGlassStore,
    evidence: SharedEvidence,
}

impl BreakGlassGate {
    pub fn new(
        inner: Arc<dyn AuthzGate>,
        store: SharedBreakGlassStore,
        evidence: SharedEvidence,
    ) -> Self {
        Self {
            inner,
            store,
            evidence,
        }
    }

    /// Attempt to override a `Deny` for the given call.
    /// Returns `Some(token)` iff a single-use claim
    /// succeeded; `None` means "no usable token" and the
    /// caller surfaces the original Deny.
    ///
    /// Walks candidates in store-order, applying AMR
    /// gate first (cheap, in-memory) before attempting
    /// the conditional UPDATE (DB round-trip). Stops at
    /// the first winning claim.
    /// Read-only twin of [`Self::try_override`]: would any live token
    /// apply to this call, without claiming one? Same candidate listing
    /// and the same scope/AMR filters, but never `try_claim`. Errors
    /// return `true` — for an advisory probe the safe direction is
    /// "might apply, don't act early", the opposite of the consuming
    /// path's fall-through-to-Deny (which must never allow on a blind
    /// spot).
    async fn override_could_apply(&self, facts: &waygate_core::Facts) -> bool {
        let principal_amr: Vec<String> = Vec::new();
        let fq = format!("{}.{}", facts.resource.server, facts.resource.tool);
        let tenant = facts.tenant.tenant_id.as_str();
        let sub = facts.principal.sub.as_str();
        match self.store.list_candidates(tenant, sub, &fq).await {
            Ok(candidates) => candidates.iter().any(|token| {
                scope_pattern_matches(&token.scope_pattern, &fq)
                    && amr_subset_satisfied(&token.requires_amr, &principal_amr)
            }),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    %tenant,
                    %sub,
                    %fq,
                    "break-glass probe lookup failed; treating as possibly-applicable",
                );
                true
            }
        }
    }

    async fn try_override(
        &self,
        facts: &waygate_core::Facts,
    ) -> Option<crate::break_glass::BreakGlassToken> {
        // The principal's AMR list is empty today
        // (`Principal` doesn't carry one). The admin
        // handler enforces "no non-empty requires_amr"
        // at mint time, so every candidate's
        // requires_amr is `&[]` and the subset check
        // always passes. The helper call is kept here so
        // that the PrincipalFacts.amr work, when it
        // lands, only needs to plumb the value through
        // — the gate logic doesn't move.
        let principal_amr: Vec<String> = Vec::new();
        let fq = format!("{}.{}", facts.resource.server, facts.resource.tool);

        let tenant = facts.tenant.tenant_id.as_str();
        let sub = facts.principal.sub.as_str();
        let candidates = match self.store.list_candidates(tenant, sub, &fq).await {
            Ok(c) => c,
            Err(e) => {
                // DB blip on the override lookup must not
                // silently allow — fall through to the
                // original Deny. WARN so an operator
                // sees the override attempt happened
                // but didn't succeed.
                tracing::warn!(
                    error = %e,
                    %tenant,
                    %sub,
                    %fq,
                    "break-glass list_candidates failed; falling through to original Deny",
                );
                record_break_glass_use("lookup_error");
                return None;
            }
        };

        for token in candidates {
            // Defense in depth: re-check the scope_pattern
            // here too, even though list_candidates
            // already filtered. A future store impl that
            // does the filter SQL-side would still pass
            // through this in-memory check unchanged.
            if !scope_pattern_matches(&token.scope_pattern, &fq) {
                continue;
            }
            if !amr_subset_satisfied(&token.requires_amr, &principal_amr) {
                record_break_glass_use("amr_unmet");
                continue;
            }
            match self.store.try_claim(token.id).await {
                Ok(Some(claimed)) => {
                    record_break_glass_use("claimed");
                    return Some(claimed);
                }
                Ok(None) => {
                    // Raced or expired between the
                    // candidate scan and the claim;
                    // try the next one.
                    record_break_glass_use("claim_raced");
                    continue;
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        token_id = %token.id,
                        "break-glass try_claim failed; trying next candidate",
                    );
                    record_break_glass_use("claim_error");
                    continue;
                }
            }
        }
        None
    }
}

#[async_trait]
impl AuthzGate for BreakGlassGate {
    async fn may_discover_server(&self, principal: &Principal, server: &str) -> bool {
        // Discovery is unchanged by break-glass — the
        // override is a per-call escape hatch, not a
        // visibility one. Pass through to the inner gate.
        self.inner.may_discover_server(principal, server).await
    }

    async fn may_list_resources(&self, principal: &Principal, server: &str) -> bool {
        self.inner.may_list_resources(principal, server).await
    }

    /// Break-glass does NOT extend to resource reads, and this delegation is
    /// the deliberate position rather than an oversight.
    ///
    /// A break-glass token authorizes a `scope_pattern` matched against a
    /// fully-qualified tool name. A resource is identified by a URI, which that
    /// pattern language cannot address: there is no tool name to match, and
    /// reusing the tool pattern against a URI would silently give every token
    /// minted for a tool an unintended reach over an upstream's data surface.
    /// Overriding a resource deny needs a scope model that names URI space, and
    /// until one exists the correct behaviour is to pass Cedar's verdict
    /// through untouched.
    ///
    /// Delegating also keeps a read from consuming a single-use token: an
    /// operator's emergency token must still be there for the dispatch it was
    /// minted for.
    async fn authorize_resource_read(
        &self,
        principal: &Principal,
        server: &str,
        uri: &str,
        risk: waygate_core::RiskTier,
    ) -> AuthzVerdict {
        self.inner
            .authorize_resource_read(principal, server, uri, risk)
            .await
    }

    async fn authorize_skill_list(
        &self,
        principal: &Principal,
        facts: &SkillAccessFacts,
    ) -> AuthzVerdict {
        self.inner.authorize_skill_list(principal, facts).await
    }

    async fn authorize_skill_fetch(
        &self,
        principal: &Principal,
        facts: &SkillAccessFacts,
    ) -> AuthzVerdict {
        self.inner.authorize_skill_fetch(principal, facts).await
    }

    async fn authorize_skill_read(
        &self,
        principal: &Principal,
        facts: &SkillAccessFacts,
    ) -> AuthzVerdict {
        self.inner.authorize_skill_read(principal, facts).await
    }

    /// The trait default for `may_call_tool` would
    /// delegate to `authorize_tool_call`, which is the
    /// path the override is wired into. That would burn
    /// the single-use token on a `tools/list`,
    /// `searchTools`, or `mode=types` call (waygate-mcp's
    /// server.rs filters those through `may_call_tool`) —
    /// the operator's emergency token would be consumed
    /// by a routine catalog refresh BEFORE the incident-
    /// response dispatch happens, and the actual
    /// dispatch would then be denied because `used_at`
    /// is already set.
    ///
    /// Override `may_call_tool` to delegate to the inner
    /// gate's `may_call_tool` — discovery sees Cedar's
    /// raw verdict, NEVER the override. The override is
    /// reserved for `authorize_tool_call` which the
    /// invocation pipeline calls exactly once per
    /// `tools/call` dispatch.
    async fn may_call_tool(&self, principal: &Principal, facts: &ToolFacts) -> AuthzVerdict {
        self.inner.may_call_tool(principal, facts).await
    }

    /// Channel-aware discovery (Code Mode binding admission) is still
    /// discovery: delegate to the inner gate so enumerating candidate
    /// bindings can never claim — and burn — a single-use break-glass
    /// token. The override stays reserved for `authorize_tool_call`, the
    /// once-per-dispatch call.
    async fn may_call_tool_on_channel(
        &self,
        principal: &Principal,
        facts: &ToolFacts,
        channel: waygate_core::InvocationChannelFact,
    ) -> AuthzVerdict {
        self.inner
            .may_call_tool_on_channel(principal, facts, channel)
            .await
    }

    /// The non-consuming probe MUST NOT reach this gate's consuming
    /// `authorize_tool_call` (the trait default would): an advisory
    /// probe that claimed the single-use token would burn the
    /// operator's emergency authorization before the real dispatch —
    /// the same failure mode `may_call_tool`'s override prevents for
    /// discovery. Probe the inner gate, and when it denies, report
    /// whether a live token *could* convert that Deny (read-only
    /// candidate scan, never a claim) so the advisory caller falls
    /// through to the pipeline instead of refusing a call the real
    /// evaluation would have allowed.
    async fn probe_tool_call(&self, facts: &waygate_core::Facts) -> ProbeVerdict {
        let inner = self.inner.probe_tool_call(facts).await;
        let ProbeVerdict::Settled(AuthzVerdict::Deny { .. }) = &inner else {
            return inner;
        };
        if self.override_could_apply(facts).await {
            // A live token could convert this Deny — and only the
            // pipeline's consuming evaluation may perform that claim,
            // its BreakGlassUse audit row, and its metric samples. The
            // advisory caller must stand fully aside.
            ProbeVerdict::ConsumingOverridePossible
        } else {
            inner
        }
    }

    async fn authorize_tool_call(&self, facts: &waygate_core::Facts) -> AuthzVerdict {
        let verdict = self.inner.authorize_tool_call(facts).await;

        // Only Deny triggers the override path. Allow
        // doesn't need one; StepUpRequired is a "do MFA
        // and try again" prompt — the operator path for
        // bypassing THAT is to mint a token AFTER doing
        // step-up, then retry; the override happens on
        // the retry's Deny if step-up still doesn't
        // resolve.
        let denied_reason = match &verdict {
            AuthzVerdict::Deny { reason, .. } => reason.clone(),
            // ApprovalRequired is not a Deny: the call proceeds through the
            // grant-claiming approval stage, which is the governed override
            // path for it. Break-glass never converts an approval gate into
            // an ungoverned allow.
            AuthzVerdict::Allow { .. }
            | AuthzVerdict::StepUpRequired { .. }
            | AuthzVerdict::ApprovalRequired { .. } => return verdict,
        };

        let Some(token) = self.try_override(facts).await else {
            return verdict;
        };

        // Audit-construction invariants:
        // - `with_tenant` so the row is stamped with the
        //   ACTUAL tenant (Facts already carry the
        //   authoritative value, and the wrapper has no
        //   `Principal` to pass to `with_principal`).
        //   Without this, every break-glass event would
        //   audit to `default` regardless of the principal's
        //   real tenant — making cross-tenant after-action
        //   review impossible.
        // - `record_required` (not best_effort) so an audit
        //   write failure short-circuits the override: if
        //   we can't write the "this happened" row, we
        //   don't allow the call. Best-effort would have
        //   let dispatch proceed even when the audit
        //   trail dropped — exactly the gap the
        //   one-row-per-use guarantee is supposed to
        //   close.
        // - principal_sub is plumbed into the reason
        //   string (the wrapper has facts, not Principal,
        //   so `with_principal` isn't available — but the
        //   sub is on facts.principal).
        let audit = AuditEvent::new("BreakGlassUse", AuditOutcome::Success)
            .with_category(EvidenceCategory::AdminMutation)
            .with_tenant(facts.tenant.tenant_id.clone())
            .with_tool(facts.resource.server.as_str(), facts.resource.tool.as_str())
            .with_risk(facts.resource.risk)
            .with_pii(facts.resource.pii)
            .with_reason(format!(
                "break-glass override: token={} issued_to={} issued_by={} \
                 acting_principal_sub={} mint_reason={:?} overrode Deny: {}",
                token.id,
                token.issued_to,
                token.issued_by,
                facts.principal.sub,
                token.reason,
                denied_reason,
            ));

        if let Err(e) = self.evidence.record_required(audit).await {
            // Audit insert failed AFTER the token was
            // already claimed. We can't un-mark `used_at`
            // race-safely from here (would require a
            // compensating tx that races every other
            // concurrent claim attempt), so the token is
            // burned. Fail closed: return the original
            // Deny + a distinct metric outcome so the
            // operator sees "I minted a token, the gateway
            // ate it without dispatching" instead of
            // dispatching without an audit row. Issue #151
            // tracks the tx-aware EvidenceRecorder that
            // would let us atomically pair the claim and
            // the audit insert.
            tracing::error!(
                error = %e,
                token_id = %token.id,
                tenant = %facts.tenant.tenant_id.as_str(),
                server = %facts.resource.server,
                tool = %facts.resource.tool,
                "break-glass: audit `record_required` failed AFTER token claim — \
                 refusing to dispatch (token is burned; operator must mint another)",
            );
            record_break_glass_use("audit_failed");
            return verdict;
        }

        tracing::warn!(
            token_id = %token.id,
            issued_by = %token.issued_by,
            issued_to = %token.issued_to,
            tenant = %facts.tenant.tenant_id.as_str(),
            server = %facts.resource.server,
            tool = %facts.resource.tool,
            mint_reason = %token.reason,
            overridden_deny = %denied_reason,
            "break-glass token CLAIMED — Deny overridden",
        );

        // A break-glass override is an operator-token escape hatch, not a
        // Cedar permit — there is no fired Cedar policy to attribute the
        // allow to, so the policy_ids are empty (the BreakGlassUse audit row
        // above carries the token id + minting admin instead).
        AuthzVerdict::Allow {
            policy_ids: Vec::new(),
        }
    }

    /// Built-in (forbid-overlay) authorization. Delegate to the inner
    /// gate's strict [`authorize_builtin_call`](AuthzGate::authorize_builtin_call)
    /// so the Cedar-backed fail-closed path runs — WITHOUT this override the
    /// trait default would route through `may_call_tool` (which this wrapper
    /// points at the inner gate's lenient `authorize_tool_call`), and an
    /// authorization-engine error would be seen as a proceed-able baseline
    /// deny. Forwarding to the inner strict path makes the wrapped
    /// production gate `BreakGlassGate(CedarGate(..))` fail closed
    /// on `BuiltinAuthz::Indeterminate` exactly as the bare `CedarGate` does.
    ///
    /// Break-glass override is deliberately NOT extended to built-in
    /// governance: the single-use-token escape hatch is for the upstream tool
    /// plane's Cedar denies, and applying it here would risk turning an
    /// engine-error `Indeterminate` into a proceed. The gateway's own control
    /// plane stays governed by its scope floor + Cedar forbids; an operator who
    /// must reach a forbidden built-in edits the policy rather than burning a
    /// break-glass token. The inner verdict (`Proceed` / `Forbidden` /
    /// `StepUpRequired` / `Indeterminate`) is returned unchanged.
    async fn authorize_builtin_call(
        &self,
        principal: &Principal,
        facts: &ToolFacts,
    ) -> BuiltinAuthz {
        self.inner.authorize_builtin_call(principal, facts).await
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use uuid::Uuid;
    use waygate_core::Facts;
    use waygate_mcp::audit::{NullSink, SharedEvidence};
    use waygate_mcp::protocol::RiskTier;

    use super::*;
    use crate::break_glass::{
        BreakGlassError, BreakGlassLifecycle, BreakGlassStore, BreakGlassToken, NewBreakGlassToken,
    };

    /// Inner gate whose built-in authorization returns a fixed verdict, so we
    /// can assert `BreakGlassGate` FORWARDS it rather than hitting the trait
    /// default (which would map a baseline-shaped Deny to `Proceed`).
    struct FixedInner(BuiltinAuthz);

    #[async_trait]
    impl AuthzGate for FixedInner {
        async fn may_discover_server(&self, _p: &Principal, _s: &str) -> bool {
            true
        }
        async fn authorize_tool_call(&self, _f: &Facts) -> AuthzVerdict {
            AuthzVerdict::Allow {
                policy_ids: Vec::new(),
            }
        }
        async fn authorize_builtin_call(&self, _p: &Principal, _f: &ToolFacts) -> BuiltinAuthz {
            self.0.clone()
        }
    }

    /// Store that is never consulted on the built-in path — the override
    /// forwards to the inner gate without attempting a token claim.
    struct UnusedStore;

    #[async_trait]
    impl BreakGlassStore for UnusedStore {
        async fn mint(
            &self,
            _m: NewBreakGlassToken<'_>,
        ) -> Result<BreakGlassToken, BreakGlassError> {
            unimplemented!("store is not consulted on the built-in path")
        }
        async fn list(
            &self,
            _t: &str,
            _l: Option<BreakGlassLifecycle>,
            _lim: u32,
            _off: u32,
        ) -> Result<Vec<BreakGlassToken>, BreakGlassError> {
            unimplemented!()
        }
        async fn delete(&self, _t: &str, _id: Uuid) -> Result<bool, BreakGlassError> {
            unimplemented!()
        }
        async fn list_candidates(
            &self,
            _t: &str,
            _s: &str,
            _fq: &str,
        ) -> Result<Vec<BreakGlassToken>, BreakGlassError> {
            unimplemented!()
        }
        async fn try_claim(&self, _id: Uuid) -> Result<Option<BreakGlassToken>, BreakGlassError> {
            unimplemented!()
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
            auth_method: waygate_oidc::AuthMethod::Oauth,
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

    fn gate(inner: BuiltinAuthz) -> BreakGlassGate {
        let store: SharedBreakGlassStore = Arc::new(UnusedStore);
        let evidence: SharedEvidence = Arc::new(NullSink);
        BreakGlassGate::new(Arc::new(FixedInner(inner)), store, evidence)
    }

    // The production gate is BreakGlassGate(CedarGate(..)). Without this
    // override the wrapper hits the trait default, routing the built-in path
    // through `may_call_tool` and turning the strict `Indeterminate` (engine
    // error) into a proceed-able baseline deny — fail open. Assert the
    // wrapper FORWARDS the inner strict verdict so `Indeterminate` stays
    // `Indeterminate` (overlay fails closed).
    #[tokio::test]
    async fn break_glass_forwards_indeterminate_unchanged() {
        let v = gate(BuiltinAuthz::Indeterminate {
            reason: "boom".into(),
        })
        .authorize_builtin_call(&principal(), &control_facts())
        .await;
        assert!(
            matches!(v, BuiltinAuthz::Indeterminate { .. }),
            "BreakGlassGate must forward the inner strict verdict, got {v:?}"
        );
    }

    // Break-glass override is intentionally NOT extended to built-in
    // governance: a Forbidden built-in stays Forbidden (the single-use-token
    // escape hatch is for the upstream tool plane's Cedar denies).
    #[tokio::test]
    async fn break_glass_does_not_override_built_in_forbid() {
        let v = gate(BuiltinAuthz::Forbidden {
            reason: "locked".into(),
            policy_ids: vec!["50-gateway-control".into()],
            reasons: vec![],
        })
        .authorize_builtin_call(&principal(), &control_facts())
        .await;
        assert!(matches!(v, BuiltinAuthz::Forbidden { .. }), "got {v:?}");
    }
}

#[cfg(test)]
mod probe_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use time::OffsetDateTime;
    use uuid::Uuid;
    use waygate_core::Facts;
    use waygate_mcp::audit::SharedEvidence;

    use super::*;
    use crate::break_glass::{
        BreakGlassError, BreakGlassLifecycle, BreakGlassStore, BreakGlassToken, NewBreakGlassToken,
    };

    /// Inner gate that always denies — the shape the override exists for.
    struct DenyInner;

    #[async_trait]
    impl AuthzGate for DenyInner {
        async fn may_discover_server(&self, _p: &Principal, _s: &str) -> bool {
            true
        }
        async fn authorize_tool_call(&self, _f: &Facts) -> AuthzVerdict {
            AuthzVerdict::Deny {
                reason: "cedar said no".into(),
                policy_ids: vec!["forbid0".into()],
                reasons: vec!["cedar said no".into()],
            }
        }
        /// Distinctive on purpose. The trait default also denies, so a test
        /// that only checked the variant could not tell a working delegation
        /// from a deleted override — both would look like a deny. These
        /// values appear nowhere else, so asserting them proves the inner
        /// gate's verdict is what came back.
        async fn authorize_resource_read(
            &self,
            _p: &Principal,
            _s: &str,
            _uri: &str,
            _risk: waygate_core::RiskTier,
        ) -> AuthzVerdict {
            AuthzVerdict::Deny {
                reason: "cedar refused the resource".into(),
                policy_ids: vec!["forbid-resource-0".into()],
                reasons: vec!["cedar refused the resource".into()],
            }
        }
    }

    /// Store scripted with candidates; counts `try_claim` calls so the
    /// probe can prove it never claims.
    struct CountingStore {
        candidates: Result<Vec<BreakGlassToken>, ()>,
        claims: AtomicUsize,
    }

    #[async_trait]
    impl BreakGlassStore for CountingStore {
        async fn mint(
            &self,
            _m: NewBreakGlassToken<'_>,
        ) -> Result<BreakGlassToken, BreakGlassError> {
            unimplemented!()
        }
        async fn list(
            &self,
            _t: &str,
            _l: Option<BreakGlassLifecycle>,
            _lim: u32,
            _off: u32,
        ) -> Result<Vec<BreakGlassToken>, BreakGlassError> {
            unimplemented!()
        }
        async fn delete(&self, _t: &str, _id: Uuid) -> Result<bool, BreakGlassError> {
            unimplemented!()
        }
        async fn list_candidates(
            &self,
            _t: &str,
            _s: &str,
            _fq: &str,
        ) -> Result<Vec<BreakGlassToken>, BreakGlassError> {
            self.candidates
                .clone()
                .map_err(|()| BreakGlassError::Database(sqlx::Error::PoolClosed))
        }
        async fn try_claim(&self, id: Uuid) -> Result<Option<BreakGlassToken>, BreakGlassError> {
            self.claims.fetch_add(1, Ordering::SeqCst);
            Ok(Some(token(id)))
        }
    }

    fn token(id: Uuid) -> BreakGlassToken {
        BreakGlassToken {
            id,
            tenant_id: "default".into(),
            issued_to: "p".into(),
            issued_by: "op".into(),
            reason: "incident".into(),
            scope_pattern: "sig.*".into(),
            requires_amr: Vec::new(),
            expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
            used_at: None,
            created_at: OffsetDateTime::now_utc(),
        }
    }

    fn principal() -> Principal {
        Principal {
            sub: "p".into(),
            email: None,
            groups: vec![],
            issuer: "test".into(),
            scopes: vec![],
            tenant: waygate_core::TenantId::default(),
            auth_method: waygate_oidc::AuthMethod::Oauth,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        }
    }

    fn deny_facts() -> Facts {
        let principal = principal();
        let tool = ToolFacts {
            server: "sig".into(),
            name: "send".into(),
            risk: waygate_mcp::protocol::RiskTier::High,
            side_effects: true,
            pii: false,
            requires_approval: false,
            requires_approval_known: true,
        };
        waygate_mcp::authz::build_call_facts(&principal, &tool)
    }

    fn gate_with(store: Arc<CountingStore>) -> BreakGlassGate {
        // A real recorder: the consuming path's override requires the
        // BreakGlassUse audit row to persist (record_required), so a
        // NullSink would abort the claim and mask what this suite pins.
        let evidence: SharedEvidence = Arc::new(waygate_mcp::audit::InMemorySink::new());
        BreakGlassGate::new(Arc::new(DenyInner), store, evidence)
    }

    /// An advisory probe over a live token reports "could allow" without
    /// claiming anything — and the real dispatch's consuming evaluation
    /// afterwards still finds the token and claims it exactly once.
    #[tokio::test]
    async fn probe_never_claims_and_leaves_the_token_for_the_dispatch() {
        let store = Arc::new(CountingStore {
            candidates: Ok(vec![token(Uuid::from_u128(1))]),
            claims: AtomicUsize::new(0),
        });
        let gate = gate_with(store.clone());
        let facts = deny_facts();

        let probed = gate.probe_tool_call(&facts).await;
        assert!(
            matches!(probed, ProbeVerdict::ConsumingOverridePossible),
            "a live token means only the pipeline may decide (and claim)",
        );
        assert_eq!(
            store.claims.load(Ordering::SeqCst),
            0,
            "the probe must not burn the operator's single-use token",
        );

        let real = gate.authorize_tool_call(&facts).await;
        assert!(matches!(real, AuthzVerdict::Allow { .. }));
        assert_eq!(
            store.claims.load(Ordering::SeqCst),
            1,
            "the dispatch's consuming evaluation claims exactly once",
        );
    }

    #[tokio::test]
    async fn probe_with_no_token_reports_the_inner_deny() {
        let store = Arc::new(CountingStore {
            candidates: Ok(Vec::new()),
            claims: AtomicUsize::new(0),
        });
        let gate = gate_with(store.clone());
        let probed = gate.probe_tool_call(&deny_facts()).await;
        assert!(matches!(
            probed,
            ProbeVerdict::Settled(AuthzVerdict::Deny { .. })
        ));
        assert_eq!(store.claims.load(Ordering::SeqCst), 0);
    }

    /// A store blip on the probe leans the safe way for an advisory
    /// caller — "might apply, don't act early" — the opposite of the
    /// consuming path, whose blind spot must fall through to Deny.
    #[tokio::test]
    async fn probe_lookup_error_reports_possibly_applicable() {
        let store = Arc::new(CountingStore {
            candidates: Err(()),
            claims: AtomicUsize::new(0),
        });
        let gate = gate_with(store.clone());
        let probed = gate.probe_tool_call(&deny_facts()).await;
        assert!(matches!(probed, ProbeVerdict::ConsumingOverridePossible));
        assert_eq!(store.claims.load(Ordering::SeqCst), 0);
    }

    /// Break-glass reaches tool calls and NOT resource reads. A token's
    /// `scope_pattern` names a fully-qualified tool, which cannot address a
    /// resource URI — so a token live enough to override a tool call leaves a
    /// resource deny standing, and stays unclaimed for the dispatch it was
    /// minted for. Pinned because the pass-through is a decision, and a later
    /// reader would otherwise be unable to tell it from a missing override.
    #[tokio::test]
    async fn break_glass_does_not_override_or_burn_a_token_on_a_resource_read() {
        let store = Arc::new(CountingStore {
            candidates: Ok(vec![token(Uuid::from_u128(1))]),
            claims: AtomicUsize::new(0),
        });
        let gate = gate_with(store.clone());

        let verdict = gate
            .authorize_resource_read(
                &principal(),
                "example-catalog",
                "example-catalog://example-guides/design-v1",
                waygate_core::RiskTier::Low,
            )
            .await;
        // The INNER gate's verdict, intact — not merely "some deny". The trait
        // default denies too, so asserting the variant alone would pass just as
        // happily if the override were deleted; only the inner gate produces
        // these reason and policy values.
        match &verdict {
            AuthzVerdict::Deny {
                reason, policy_ids, ..
            } => {
                assert_eq!(reason, "cedar refused the resource");
                assert_eq!(policy_ids, &vec!["forbid-resource-0".to_owned()]);
            }
            other => panic!("a resource deny must stand even with a live token; got {other:?}"),
        }
        assert_eq!(
            store.claims.load(Ordering::SeqCst),
            0,
            "a resource read must not consume the operator's single-use token",
        );

        // Same token, same gate: the tool plane still overrides, so the
        // pass-through above is scoped to resources rather than a dead store.
        assert!(matches!(
            gate.authorize_tool_call(&deny_facts()).await,
            AuthzVerdict::Allow { .. }
        ));
        assert_eq!(store.claims.load(Ordering::SeqCst), 1);
    }
}
