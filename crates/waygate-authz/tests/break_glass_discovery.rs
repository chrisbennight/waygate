//! Pin that `BreakGlassGate::may_call_tool` does NOT consult the
//! store / claim a token.
//!
//! The trait default for `may_call_tool` delegates to
//! `authorize_tool_call`. If `BreakGlassGate` inherits
//! that default, then EVERY discovery hop —
//! `tools/list`, `searchTools`, `mode=types` — would
//! burn a single-use token via the override path,
//! consuming the operator's emergency token on a
//! routine catalog refresh and leaving the actual
//! incident-response dispatch denied because `used_at`
//! is already set.
//!
//! Fix: `BreakGlassGate` overrides `may_call_tool` to
//! delegate to the inner gate's `may_call_tool` —
//! discovery sees the raw Cedar verdict, never the
//! override. This test pins that contract: an inner
//! gate that always returns Deny, paired with a store
//! that would happily claim a token, must NOT see any
//! claim attempts when `may_call_tool` fires.

use std::sync::Arc;
use std::sync::Mutex;

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use waygate_authz::{
    BreakGlassError, BreakGlassGate, BreakGlassStore, BreakGlassToken, NewBreakGlassToken,
};
use waygate_mcp::audit::{NullSink, SharedEvidence};
use waygate_mcp::authz::{AuthzGate, AuthzVerdict, ToolFacts};
use waygate_mcp::protocol::RiskTier;
use waygate_oidc::{AuthMethod, Principal};

/// Inner gate that ALWAYS denies. Discovery (via the
/// trait default `may_call_tool` ⇒ `authorize_tool_call`)
/// would, if BreakGlassGate didn't override
/// `may_call_tool`, trigger the override path on this
/// Deny.
struct AlwaysDeny;

#[async_trait]
impl AuthzGate for AlwaysDeny {
    async fn may_discover_server(&self, _principal: &Principal, _server: &str) -> bool {
        true
    }
    async fn authorize_tool_call(&self, _facts: &waygate_core::Facts) -> AuthzVerdict {
        AuthzVerdict::Deny {
            reason: "always-deny test gate".into(),
            policy_ids: vec![],
            reasons: vec![],
        }
    }
}

/// Recording store: every store call (`list_candidates`,
/// `try_claim`) increments a counter so the test can
/// pin "the store was / was not consulted." Returns
/// empty / None for everything since we don't actually
/// want to override; we just want to detect the
/// attempt.
#[derive(Default)]
struct RecordingStore {
    list_candidates_calls: Mutex<u32>,
    try_claim_calls: Mutex<u32>,
}

impl RecordingStore {
    fn list_calls(&self) -> u32 {
        *self.list_candidates_calls.lock().unwrap()
    }
    fn claim_calls(&self) -> u32 {
        *self.try_claim_calls.lock().unwrap()
    }
}

#[async_trait]
impl BreakGlassStore for RecordingStore {
    async fn mint(
        &self,
        _grant: NewBreakGlassToken<'_>,
    ) -> Result<BreakGlassToken, BreakGlassError> {
        unimplemented!("test fixture")
    }
    async fn list(
        &self,
        _tenant_id: &str,
        _lifecycle: Option<waygate_authz::BreakGlassLifecycle>,
        _limit: u32,
        _offset: u32,
    ) -> Result<Vec<BreakGlassToken>, BreakGlassError> {
        unimplemented!("test fixture")
    }
    async fn delete(&self, _tenant_id: &str, _token_id: Uuid) -> Result<bool, BreakGlassError> {
        unimplemented!("test fixture")
    }
    async fn list_candidates(
        &self,
        _tenant_id: &str,
        _principal_sub: &str,
        _fq_tool_name: &str,
    ) -> Result<Vec<BreakGlassToken>, BreakGlassError> {
        *self.list_candidates_calls.lock().unwrap() += 1;
        Ok(Vec::new())
    }
    async fn try_claim(&self, _token_id: Uuid) -> Result<Option<BreakGlassToken>, BreakGlassError> {
        *self.try_claim_calls.lock().unwrap() += 1;
        Ok(None)
    }
}

fn principal_acme() -> Principal {
    Principal {
        sub: "alice".into(),
        email: None,
        groups: vec![],
        issuer: "https://idp.test".into(),
        scopes: vec![],
        tenant: waygate_core::TenantId::parse("acme").unwrap_or_default(),
        auth_method: AuthMethod::Oauth,
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}

fn tool_facts() -> ToolFacts {
    ToolFacts {
        server: "billing".into(),
        name: "charge".into(),
        risk: RiskTier::High,
        side_effects: true,
        pii: false,
        requires_approval: false,
        requires_approval_known: true,
    }
}

#[tokio::test]
async fn may_call_tool_does_not_consult_break_glass_store() {
    // Trait default would route may_call_tool → authorize_tool_call
    // → override path → store.list_candidates / try_claim. The
    // override on BreakGlassGate must prevent that.
    let inner: Arc<dyn AuthzGate> = Arc::new(AlwaysDeny);
    let store = Arc::new(RecordingStore::default());
    let evidence: SharedEvidence = Arc::new(NullSink);
    let gate = BreakGlassGate::new(inner, store.clone(), evidence);

    let principal = principal_acme();
    let facts = tool_facts();

    let verdict = gate.may_call_tool(&principal, &facts).await;
    // Match by reference so the assertion message can
    // still format `{verdict:?}` (AuthzVerdict is Clone
    // but not Copy; the by-value match in `matches!`
    // would otherwise be a move-after-use under stricter
    // borrow-check).
    assert!(
        matches!(&verdict, AuthzVerdict::Deny { .. }),
        "must surface the inner gate's Deny unchanged; got {verdict:?}",
    );
    assert_eq!(
        store.list_calls(),
        0,
        "may_call_tool MUST NOT consult the store — discovery hops would burn the token",
    );
    assert_eq!(
        store.claim_calls(),
        0,
        "may_call_tool MUST NOT attempt try_claim — single-use tokens would be consumed on tools/list",
    );
}

#[tokio::test]
async fn channel_aware_discovery_does_not_consult_break_glass_store() {
    // Code Mode binding admission enumerates candidate tools through
    // may_call_tool_on_channel. Like may_call_tool, it is discovery: the
    // trait default would route through authorize_tool_call and burn a
    // single-use token per enumerated Deny — the BreakGlassGate override
    // must delegate to the inner gate instead.
    let inner: Arc<dyn AuthzGate> = Arc::new(AlwaysDeny);
    let store = Arc::new(RecordingStore::default());
    let evidence: SharedEvidence = Arc::new(NullSink);
    let gate = BreakGlassGate::new(inner, store.clone(), evidence);

    let verdict = gate
        .may_call_tool_on_channel(
            &principal_acme(),
            &tool_facts(),
            waygate_core::InvocationChannelFact::CodeMode,
        )
        .await;
    assert!(
        matches!(&verdict, AuthzVerdict::Deny { .. }),
        "must surface the inner gate's Deny unchanged; got {verdict:?}",
    );
    assert_eq!(
        store.list_calls(),
        0,
        "channel-aware discovery MUST NOT consult the store — binding enumeration would burn the token",
    );
    assert_eq!(store.claim_calls(), 0);
}

#[tokio::test]
async fn authorize_tool_call_does_still_consult_the_store_on_deny() {
    // Defense in depth: confirm the override path is
    // wired on the right call. Pin that authorize_tool_call
    // (the actual dispatch path) DOES go through
    // list_candidates on Deny so the may_call_tool
    // override above doesn't accidentally short-circuit
    // both paths.
    let inner: Arc<dyn AuthzGate> = Arc::new(AlwaysDeny);
    let store = Arc::new(RecordingStore::default());
    let evidence: SharedEvidence = Arc::new(NullSink);
    let gate = BreakGlassGate::new(inner, store.clone(), evidence);

    let facts = build_facts();
    let _ = gate.authorize_tool_call(&facts).await;
    assert_eq!(
        store.list_calls(),
        1,
        "authorize_tool_call MUST consult list_candidates on Deny",
    );
}

fn build_facts() -> waygate_core::Facts {
    waygate_core::Facts {
        principal: waygate_core::PrincipalFacts {
            sub: "alice".into(),
            email: None,
            groups: vec![],
            scopes: vec![],
            auth_method: "oauth".into(),
            roles: vec![],
            scim: None,
        },
        client: waygate_core::ClientFacts::default(),
        tenant: waygate_core::TenantFacts {
            tenant_id: waygate_core::TenantId::parse("acme").unwrap_or_default(),
        },
        action: waygate_core::ActionFacts {
            kind: "CallTool".into(),
            required_scope: None,
        },
        resource: waygate_core::ResourceFacts {
            server: "billing".into(),
            tool: "charge".into(),
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
            resource_type: Some("Tool".into()),
            operation: None,
        },
        request: None,
        context: waygate_core::RuntimeContextFacts {
            approval_present: false,
            mfa: false,
            time: OffsetDateTime::now_utc(),
            source_ip: None,
            channel: waygate_core::InvocationChannelFact::Direct,
        },
    }
}
