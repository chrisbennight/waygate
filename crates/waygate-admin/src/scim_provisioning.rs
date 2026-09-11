//! Shared helper that appends a SCIM mutation event
//! to the `scim_provisioning_log` table.
//!
//! Lives next to `scim_users` / `scim_groups` so both handler
//! modules share one writer instead of each open-coding the
//! `state.identity.scim_provisioning_log.as_ref()` plumbing. Best-
//! effort by contract — the SCIM mutation has already
//! committed by the time we get here; a log failure logs +
//! drops rather than rolling back the SCIM mutation (which
//! would leave the SCIM client and the store inconsistent).
//!
//! Distinct from the shared AdminMutation recorder (which writes to
//! `audit_log` via the `EvidenceRecorder`): that one is the
//! compliance-chain entry; this one is the dashboard-facing
//! structured timeline. The two are complementary — each
//! survives the loss of the other.

use std::sync::Arc;

use serde_json::Value;
use uuid::Uuid;
use waygate_dashboard_stores::scim_provisioning_log::{NewEntry, Outcome, TargetKind};
use waygate_oidc::Principal;

use crate::state::AdminState;

/// Append one provisioning-log entry. No-op when the store
/// isn't wired (dev mode / no DB). Errors are logged + dropped.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn append(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    target_kind: TargetKind,
    target_id: Uuid,
    target_display: &str,
    target_external_id: Option<&str>,
    action: &str,
    outcome: Outcome,
    error_message: Option<String>,
    detail: Value,
) {
    let Some(store) = state.identity.scim_provisioning_log.get() else {
        return;
    };
    let entry = NewEntry {
        tenant_id: tenant_id.to_owned(),
        target_kind,
        target_id,
        target_display: target_display.to_owned(),
        target_external_id: target_external_id.map(str::to_owned),
        action: action.to_owned(),
        outcome,
        actor_sub: actor.map(|p| p.sub.clone()),
        actor_email: actor.and_then(|p| p.email.clone()),
        error_message,
        detail,
    };
    if let Err(e) = store.append(entry).await {
        tracing::error!(
            error = %e,
            tenant = tenant_id,
            action = action,
            target_kind = target_kind.as_str(),
            target_id = %target_id,
            "scim_provisioning_log append failed; SCIM mutation already committed",
        );
    }
}
