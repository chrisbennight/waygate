//! Out-of-band notification that a change request needs a human decision
//! (the HITL control plane's away-from-desk path).
//!
//! When an agent proposes a change (over REST or the built-in MCP tools),
//! [`crate::change_requests::propose_core`] fires this notifier so a human
//! who is *away from the dashboard* still learns a decision is waiting. The
//! at-the-desk path is already covered by the dashboard review queue; this is
//! the "away from the desk" push.
//!
//! ## Security shape (Teleport's pattern)
//!
//! The notification carries only an operator-safe **summary** — action type,
//! requester, binding code, countdown — plus a **deep link** to the
//! login-gated dashboard. It deliberately does NOT carry the proposed
//! `params` or the `justification`: those live behind the authenticated
//! surface the link points to. The notification is a *link, never an approve
//! button* — approval happens behind login + step-up, never by
//! replying to an unauthenticated channel. The payload struct below has no
//! field for params/justification, so a leak is structurally impossible, not
//! merely avoided.
//!
//! ## Delivery contract
//!
//! [`ChangeRequestNotifier::notify_change_proposed`] is **fire-and-forget**:
//! it must not block the propose path (the impl spawns any network I/O) and a
//! delivery failure must never fail the propose — the change still sits in
//! the dashboard review queue regardless. This mirrors the data-plane
//! [`waygate_invocation::HitlNotifier`] contract (a sync, best-effort
//! broadcast), but for the *control-plane* change-request event, which the
//! data-plane `ApprovalHub` does not model.

use std::sync::Arc;

use time::OffsetDateTime;
use uuid::Uuid;

/// Operator-safe summary of a proposed change, for an out-of-band heads-up.
/// Carries NO `params` and NO `justification` — only what a human needs to
/// recognise the request and click through to the authenticated dashboard.
#[derive(Debug, Clone)]
pub struct ChangeProposedNotification {
    pub tenant_id: String,
    pub change_request_id: Uuid,
    /// Registry key of the proposed action (e.g. `rate_limit.update`) — a
    /// coarse summary, not the params.
    pub action_type: String,
    /// The maker (agent) that proposed the change.
    pub requested_by: String,
    /// CIBA `binding_message` short code — the operator confirms it matches
    /// what the agent surfaced before approving.
    pub binding_code: String,
    /// When the request lapses without a decision (drives the countdown).
    pub expires_at: OffsetDateTime,
    /// Login-gated dashboard deep link to the review-queue row. A link, not
    /// an approve button.
    pub approval_url: String,
}

/// Fire-and-forget out-of-band notifier for proposed change requests.
///
/// Implementations MUST NOT block the caller (spawn any network I/O) and MUST
/// NOT propagate delivery errors — see the module docs.
pub trait ChangeRequestNotifier: Send + Sync {
    /// Notify, best-effort, that a change request was proposed and needs a
    /// human decision.
    fn notify_change_proposed(&self, payload: ChangeProposedNotification);
}

/// Shared handle to a [`ChangeRequestNotifier`], injected into `AdminState`
/// (REST) and the built-in MCP tools (so both propose surfaces notify).
pub type SharedChangeNotifier = Arc<dyn ChangeRequestNotifier>;
