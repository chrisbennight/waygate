//! The one fail-closed AdminMutation evidence recorder.
//!
//! Every mutating admin REST/dashboard handler must emit an `AdminMutation`
//! evidence row via `record_required` after its store write commits.
//! A shared recorder keeps the required audit behavior consistent across
//! admin mutation handlers.
//!
//! [`record_admin_mutation`] is the single copy. Per-resource callers pass
//! their resource label and a verify hint; everything else — the event
//! shape, the required (fail-closed) write, the operator-visible 500 when
//! the mutation committed but the audit row didn't — is uniform here.
//!
//! One recorder deliberately remains outside this module:
//! `change_requests::record_mutation`. Its event shape differs in contract,
//! not by drift — it records a VARIABLE `AuditOutcome` (a denied change is a
//! `Failure` event), stamps the change's `action_type` into the structured
//! `target` column (the Overview "What changed" feed pivots on it), and maps
//! audit failure to a plain `Internal` error. Folding it would mean growing
//! this module's common signature for one caller.
//!
//! The store mutation and audit INSERT are not atomic. If the audit write
//! fails after the mutation commits, `InternalOperatorVisible` tells the
//! operator to verify the resource through its list endpoint.

use crate::error::ApiError;
use crate::state::AdminState;
use waygate_oidc::Principal;

/// Record a required (fail-closed) `AdminMutation` evidence row for a
/// committed admin mutation.
///
/// - `resource` — the admin resource label used in logs and the fallback
///   message (e.g. `"rate_limit_policies"`).
/// - `verify_hint` — where the operator can confirm the committed state when
///   the audit write failed (e.g. `"GET /api/v1/admin/rate_limit_policies"`).
/// - `tenant_id` — the TARGET tenant of the mutation (not necessarily the
///   actor's); unparseable ids fall back to the default tenant.
/// - `action` — the `audit_log.action` value (e.g.
///   `"rate_limit_policies.create"`).
/// - `reason` — human-readable mutation detail recorded on the row.
///
/// Returns `Err(ApiError::InternalOperatorVisible)` when the mutation
/// committed but the audit-of-record write failed — the caller surfaces that
/// as a 500 so the operator KNOWS the audit trail has a hole, rather than
/// silently succeeding.
pub(crate) async fn record_admin_mutation(
    state: &AdminState,
    resource: &'static str,
    verify_hint: &'static str,
    tenant_id: &str,
    actor: Option<&Principal>,
    action: &'static str,
    reason: String,
) -> Result<(), ApiError> {
    state
        .evidence
        .record_required(build_event(tenant_id, actor, action, reason))
        .await
        .map(|_event_id| ())
        .map_err(|e| {
            tracing::error!(
                error = %e,
                action = action,
                resource = resource,
                "admin mutation evidence record_required failed; mutation \
                 already committed, client received 500 — operator must \
                 verify via {verify_hint}",
            );
            ApiError::InternalOperatorVisible(format!(
                "{resource} mutation `{action}` committed but audit-of-record \
                 failed to persist; verify via {verify_hint}"
            ))
        })
}

/// The SCIM disposition: the same required (`record_required`) write, but
/// audit failure is logged loudly and DROPPED rather than surfaced. A SCIM
/// mutation is already committed by the time the row is recorded, and SCIM
/// IdP clients (Okta) retry 500s by re-mutating — surfacing the audit
/// failure as an error would cause double-provisioning, so log-and-drop is
/// the safer disposition for the SCIM protocol surface (the rationale
/// carried over from the per-file `record_scim_*` copies this replaces).
/// Every other admin surface uses [`record_admin_mutation`]'s
/// fail-closed disposition.
pub(crate) async fn record_admin_mutation_logged(
    state: &AdminState,
    resource: &'static str,
    target_id: &str,
    tenant_id: &str,
    actor: Option<&Principal>,
    action: &'static str,
    reason: String,
) {
    if let Err(e) = state
        .evidence
        .record_required(build_event(tenant_id, actor, action, reason))
        .await
    {
        // `target_id` keeps the dropped row tied to the affected resource —
        // this log line is the ONLY remaining signal for the drop, so it
        // must carry the id the deleted per-file helpers logged
        // (scim_user_id / scim_group_id).
        tracing::error!(
            error = %e,
            action = action,
            resource = resource,
            target_id = %target_id,
            "admin mutation evidence record_required failed; mutation already \
             committed (SCIM disposition: logged, not surfaced)",
        );
    }
}

/// The one `AdminMutation` event shape both dispositions record.
/// Unparseable tenant ids fall back to the default tenant, matching the
/// prior per-file copies.
fn build_event(
    tenant_id: &str,
    actor: Option<&Principal>,
    action: &'static str,
    reason: String,
) -> waygate_mcp::AuditEvent {
    let target_tenant = waygate_core::TenantId::parse(tenant_id).unwrap_or_default();
    waygate_mcp::AuditEvent::new(action, waygate_mcp::AuditOutcome::Success)
        .with_category(waygate_mcp::EvidenceCategory::AdminMutation)
        .with_principal(actor)
        .with_tenant(target_tenant)
        .with_reason(reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AdminState;
    use async_trait::async_trait;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use waygate_mcp::audit::NullSink;
    use waygate_mcp::{AuditEvent, EvidenceError, EvidenceRecorder};
    use waygate_upstream::pool::UpstreamPool;

    /// Success-path recorder: captures the event so the test can assert the
    /// shape the shared helper commits to.
    #[derive(Default)]
    struct CapturingSink {
        events: Mutex<Vec<AuditEvent>>,
    }

    #[async_trait]
    impl EvidenceRecorder for CapturingSink {
        async fn record_required(&self, event: AuditEvent) -> Result<uuid::Uuid, EvidenceError> {
            let id = event.id;
            self.events.lock().unwrap().push(event);
            Ok(id)
        }
        async fn record_chained_best_effort(&self, event: AuditEvent) {
            self.events.lock().unwrap().push(event);
        }
        async fn record_best_effort(&self, _event: AuditEvent) {}
    }

    async fn state_with(evidence: waygate_mcp::audit::SharedEvidence) -> AdminState {
        let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
        AdminState::new(
            pool,
            None,
            None,
            evidence,
            None,
            None,
            None,
            None,
            "http://127.0.0.1:0".into(),
        )
    }

    #[tokio::test]
    async fn committed_mutation_records_an_admin_mutation_event() {
        let sink = Arc::new(CapturingSink::default());
        let state = state_with(sink.clone()).await;
        record_admin_mutation(
            &state,
            "rate_limit_policies",
            "GET /api/v1/admin/rate_limit_policies",
            "default",
            None,
            "rate_limit_policies.create",
            "policy id=x".into(),
        )
        .await
        .expect("required record succeeds");
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 1, "exactly one evidence row per mutation");
        assert_eq!(events[0].action, "rate_limit_policies.create");
    }

    #[tokio::test]
    async fn logged_disposition_records_the_same_event_shape() {
        let sink = Arc::new(CapturingSink::default());
        let state = state_with(sink.clone()).await;
        record_admin_mutation_logged(
            &state,
            "scim_users",
            "user-x",
            "default",
            None,
            "scim_users.create",
            "scim user id=x".into(),
        )
        .await;
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 1, "exactly one evidence row per mutation");
        assert_eq!(events[0].action, "scim_users.create");
    }

    #[tokio::test]
    async fn logged_disposition_swallows_audit_failure_by_contract() {
        // The SCIM disposition: NullSink's record_required fails by design,
        // and the call must complete WITHOUT surfacing an error — a SCIM
        // client seeing a 500 here would retry the mutation and
        // double-provision. Completing normally IS the asserted
        // contract; the failure goes to the error log instead.
        let state = state_with(Arc::new(NullSink)).await;
        record_admin_mutation_logged(
            &state,
            "scim_users",
            "user-x",
            "default",
            None,
            "scim_users.delete",
            "scim user id=x".into(),
        )
        .await;
    }

    #[tokio::test]
    async fn audit_write_failure_is_fail_closed_and_operator_visible() {
        // NullSink's record_required fails by design — the DB-less posture.
        // The helper must surface that as InternalOperatorVisible naming the
        // action and the verify hint, never a silent success.
        let state = state_with(Arc::new(NullSink)).await;
        let err = record_admin_mutation(
            &state,
            "inspection_rules",
            "GET /api/v1/admin/inspection_rules",
            "default",
            None,
            "InspectionRuleCreated",
            "rule id=x".into(),
        )
        .await
        .expect_err("required record must fail closed");
        match err {
            ApiError::InternalOperatorVisible(msg) => {
                assert!(msg.contains("InspectionRuleCreated"), "{msg}");
                assert!(msg.contains("GET /api/v1/admin/inspection_rules"), "{msg}");
            }
            other => panic!("expected InternalOperatorVisible, got {other:?}"),
        }
    }
}
