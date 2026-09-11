//! The in-chat side-effects **approval rendezvous**.
//!
//! When the agent loop wants to run a **side-effecting** tool, its
//! `ApprovalGate` ([`crate::agent_runtime::ChatApprovalGate`]) parks the call
//! here and blocks; the operator's `POST /agent_chat/approve` resolves it. This
//! is the data-plane, in-chat counterpart to the control-plane HITL (propose →
//! review-queue): a lightweight per-call confirm, scoped to the chat session.
//!
//! **Owner scoping is a security boundary.** Every pending approval records the
//! owner `(tenant, user_sub)` of the chat session that parked it; [`resolve`]
//! only fires when the caller matches — an operator can never approve another
//! operator's agent's side-effecting call.
//!
//! [`resolve`]: ChatApprovalRegistry::resolve

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use tokio::sync::oneshot;
use uuid::Uuid;

use waygate_agent::ApprovalDecision;

/// `(session_id, call_id)`. `session_id` is a **fresh per-turn id** minted by
/// the stream handler (NOT the conversation id), and `call_id` is the model's
/// tool-call id. Keying on a per-turn id is what makes the pair collision-proof:
/// two turns of the same conversation can overlap (two browser tabs) and a
/// provider may reuse a tool-call id across turns, but their distinct
/// `session_id`s keep their approvals independent — one turn's decision can
/// never resolve another's call. Within a single turn the
/// loop is sequential (register → resolve → remove before the next call), so a
/// reused call id within a turn cannot collide either.
type Key = (Uuid, String);

/// A parked, not-yet-decided approval.
struct Pending {
    tx: oneshot::Sender<ApprovalDecision>,
    tenant: String,
    user_sub: String,
}

/// In-memory registry of parked approvals. Process-local (a chat turn's SSE
/// stream and its approve request hit the same process); nothing is persisted —
/// a pending approval that outlives the process is simply gone, and the gate's
/// timeout turns that into a rejection.
#[derive(Default)]
pub struct ChatApprovalRegistry {
    slots: Mutex<HashMap<Key, Pending>>,
}

pub type SharedChatApprovals = Arc<ChatApprovalRegistry>;

impl ChatApprovalRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Park a pending approval and return the receiver the gate awaits. The slot
    /// is inserted **before** the gate awaits, so a concurrent [`resolve`] can
    /// never miss it (no read-await-write window).
    ///
    /// [`resolve`]: Self::resolve
    pub fn register(
        &self,
        session: Uuid,
        call_id: &str,
        tenant: &str,
        user_sub: &str,
    ) -> oneshot::Receiver<ApprovalDecision> {
        let (tx, rx) = oneshot::channel();
        self.slots.lock().unwrap().insert(
            (session, call_id.to_owned()),
            Pending {
                tx,
                tenant: tenant.to_owned(),
                user_sub: user_sub.to_owned(),
            },
        );
        rx
    }

    /// Drop a parked approval without a decision (the gate timed out / the turn
    /// ended). Idempotent.
    pub fn cancel(&self, session: Uuid, call_id: &str) {
        self.slots
            .lock()
            .unwrap()
            .remove(&(session, call_id.to_owned()));
    }

    /// Apply the operator's decision to a parked approval. **Owner-scoped**: only
    /// resolves a slot whose `(tenant, user_sub)` matches the caller. Returns
    /// `true` iff a matching pending approval was found and resolved; `false`
    /// (no-op) for an unknown key or an owner mismatch — the two are
    /// indistinguishable to the caller, so a non-owner cannot probe for the
    /// existence of another operator's pending approval.
    pub fn resolve(
        &self,
        session: Uuid,
        call_id: &str,
        tenant: &str,
        user_sub: &str,
        decision: ApprovalDecision,
    ) -> bool {
        let key = (session, call_id.to_owned());
        let mut slots = self.slots.lock().unwrap();
        // Owner-check while still borrowed, then remove+send only on a match —
        // a mismatched key is left untouched (no disclosure, no consumption).
        match slots.get(&key) {
            Some(p) if p.tenant == tenant && p.user_sub == user_sub => {}
            _ => return false,
        }
        match slots.remove(&key) {
            Some(p) => p.tx.send(decision).is_ok(),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> ChatApprovalRegistry {
        ChatApprovalRegistry::new()
    }

    #[tokio::test]
    async fn register_then_resolve_delivers_decision_to_owner() {
        let r = reg();
        let s = Uuid::new_v4();
        let rx = r.register(s, "call_1", "t1", "alice");
        assert!(r.resolve(s, "call_1", "t1", "alice", ApprovalDecision::Approved));
        assert_eq!(rx.await.unwrap(), ApprovalDecision::Approved);
    }

    #[tokio::test]
    async fn resolve_rejects_non_owner() {
        let r = reg();
        let s = Uuid::new_v4();
        let _rx = r.register(s, "call_1", "t1", "alice");
        // Wrong user, wrong tenant — both must be refused, and the slot must
        // survive so the real owner can still resolve it.
        assert!(!r.resolve(s, "call_1", "t1", "mallory", ApprovalDecision::Approved));
        assert!(!r.resolve(s, "call_1", "t2", "alice", ApprovalDecision::Approved));
        assert!(r.resolve(s, "call_1", "t1", "alice", ApprovalDecision::Approved));
    }

    #[tokio::test]
    async fn same_call_id_in_different_sessions_does_not_collide() {
        // Two overlapping turns reuse a tool-call id but have distinct
        // per-turn session ids — each resolves independently, and resolving one
        // never touches the other.
        let r = reg();
        let (s1, s2) = (Uuid::new_v4(), Uuid::new_v4());
        let rx1 = r.register(s1, "call_1", "t", "alice");
        let rx2 = r.register(s2, "call_1", "t", "alice");
        // Resolve session 2 only.
        assert!(r.resolve(s2, "call_1", "t", "alice", ApprovalDecision::Approved));
        assert_eq!(rx2.await.unwrap(), ApprovalDecision::Approved);
        // Session 1 is untouched — still resolvable on its own.
        assert!(r.resolve(
            s1,
            "call_1",
            "t",
            "alice",
            ApprovalDecision::Rejected("no".into())
        ));
        assert_eq!(rx1.await.unwrap(), ApprovalDecision::Rejected("no".into()));
    }

    #[tokio::test]
    async fn resolve_unknown_key_is_false() {
        let r = reg();
        assert!(!r.resolve(
            Uuid::new_v4(),
            "nope",
            "t1",
            "alice",
            ApprovalDecision::Approved
        ));
    }

    #[tokio::test]
    async fn cancel_then_resolve_is_false() {
        let r = reg();
        let s = Uuid::new_v4();
        let _rx = r.register(s, "call_1", "t1", "alice");
        r.cancel(s, "call_1");
        assert!(!r.resolve(s, "call_1", "t1", "alice", ApprovalDecision::Approved));
    }

    #[tokio::test]
    async fn resolve_carries_rejection_reason() {
        let r = reg();
        let s = Uuid::new_v4();
        let rx = r.register(s, "c", "t", "u");
        assert!(r.resolve(
            s,
            "c",
            "t",
            "u",
            ApprovalDecision::Rejected("declined".into())
        ));
        assert_eq!(
            rx.await.unwrap(),
            ApprovalDecision::Rejected("declined".into())
        );
    }
}
