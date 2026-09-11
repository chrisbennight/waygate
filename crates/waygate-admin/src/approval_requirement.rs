//! Server-side enforcement of frozen HITL approval requirements.
//!
//! The change-request row captures the bar at proposal time. This module is
//! the single approve-time boundary that checks every dimension before the
//! store records an approval: eligible RBAC role, fresh dashboard-session
//! factors, and the proposal-age cooldown. Propose-only callers remain unable
//! to approve because the approval surface requires `mcp:admin`; an eligible
//! admin proposer counts toward the request's configured quorum.

use time::{Duration, OffsetDateTime};
use waygate_changeset::{ApprovalFactor, ApprovalRequirement, ChangeRequest};
use waygate_oidc::{Principal, Session};

use crate::change_executor::DEFAULT_ELIGIBLE_ROLE;
use crate::error::ApiError;

/// A factor must have been established within this window at the instant the
/// approval is recorded. Long-lived encrypted sessions therefore cannot turn
/// one signed authentication gesture into standing approval authority.
pub(crate) const APPROVAL_FACTOR_MAX_AGE_SECONDS: i64 = 300;
const AUTH_TIME_FUTURE_SKEW_SECONDS: i64 = 60;

/// Whether every declared requirement dimension has a concrete approve-time
/// enforcement path in this build. Break-glass-backed approval still lacks a
/// presentation/claim surface, so it remains fail-closed at proposal time.
pub(crate) fn requirement_enforceable(requirement: &ApprovalRequirement) -> bool {
    let ApprovalRequirement {
        required_approvals,
        eligible_role,
        factors,
        cooldown_seconds,
    } = requirement;

    *required_approvals >= 1
        && !eligible_role.is_empty()
        && eligible_role.trim() == eligible_role
        && cooldown_seconds.is_none_or(|seconds| seconds >= 0)
        && factors.iter().all(|factor| {
            matches!(
                ApprovalFactor::from_db_str(factor),
                Some(ApprovalFactor::Mfa | ApprovalFactor::Passkey)
            )
        })
}

/// A request must stay pending strictly longer than its cooldown; at equality
/// it expires at the same instant it first becomes approvable.
pub(crate) fn requirement_fits_ttl(requirement: &ApprovalRequirement, ttl_seconds: u32) -> bool {
    requirement
        .cooldown_seconds
        .is_none_or(|cooldown| i64::from(cooldown) < i64::from(ttl_seconds))
}

/// Enforce the frozen bar immediately before any approval-state write.
pub(crate) fn enforce_approval_requirement(
    change: &ChangeRequest,
    approver: &Principal,
    session: Option<&Session>,
    now: OffsetDateTime,
) -> Result<(), ApiError> {
    if change.eligible_role != DEFAULT_ELIGIBLE_ROLE
        && !approver
            .roles
            .iter()
            .any(|role| role == &change.eligible_role)
    {
        return Err(ApiError::ForbiddenDyn(format!(
            "approval requires RBAC role {:?}",
            change.eligible_role
        )));
    }

    if !change.required_factors.is_empty() {
        let session = session.ok_or(ApiError::Forbidden(
            "protected approval requires fresh dashboard authentication evidence",
        ))?;
        if session.principal.sub != approver.sub || session.principal.tenant != approver.tenant {
            return Err(ApiError::Forbidden(
                "dashboard assurance does not belong to the approving principal",
            ));
        }
        let assurance = &session.assurance;
        let authenticated_at = assurance.authenticated_at.ok_or(ApiError::Forbidden(
            "dashboard session has no authentication time; re-authorize before approving",
        ))?;
        let age = now
            .unix_timestamp()
            .checked_sub(authenticated_at)
            .ok_or(ApiError::Forbidden(
                "dashboard authentication time is outside the supported range; re-authorize before approving",
            ))?;
        if !(-AUTH_TIME_FUTURE_SKEW_SECONDS..=APPROVAL_FACTOR_MAX_AGE_SECONDS).contains(&age) {
            return Err(ApiError::Forbidden(
                "dashboard authentication evidence is not fresh; re-authorize before approving",
            ));
        }

        for required in &change.required_factors {
            let factor = ApprovalFactor::from_db_str(required).ok_or_else(|| {
                ApiError::InternalOperatorVisible(format!(
                    "change request {} has unknown captured approval factor {:?}; refusing approval",
                    change.id, required
                ))
            })?;
            if factor == ApprovalFactor::BreakGlass {
                return Err(ApiError::InternalOperatorVisible(format!(
                    "change request {} requires break_glass approval evidence, which this build cannot claim; refusing approval",
                    change.id
                )));
            }
            if !assurance.factors.iter().any(|held| held == required) {
                return Err(ApiError::ForbiddenDyn(format!(
                    "approval requires fresh {required} evidence"
                )));
            }
        }
    }

    if let Some(cooldown_seconds) = change.cooldown_seconds {
        if cooldown_seconds < 0 {
            return Err(ApiError::InternalOperatorVisible(format!(
                "change request {} has an invalid negative cooldown; refusing approval",
                change.id
            )));
        }
        let not_before = change
            .created_at
            .checked_add(Duration::seconds(i64::from(cooldown_seconds)))
            .ok_or_else(|| {
                ApiError::InternalOperatorVisible(format!(
                    "change request {} has an invalid cooldown boundary; refusing approval",
                    change.id
                ))
            })?;
        if now < not_before {
            return Err(ApiError::Conflict(format!(
                "approval cooldown is active until {}; the request may still be denied",
                waygate_core::fmt::format_ts_rfc3339(not_before)
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use uuid::Uuid;
    use waygate_changeset::ChangeRequestStatus;
    use waygate_oidc::{AuthMethod, SessionAssurance};

    fn requirement(
        role: &str,
        factors: &[&str],
        cooldown_seconds: Option<i32>,
    ) -> ApprovalRequirement {
        ApprovalRequirement {
            required_approvals: 1,
            eligible_role: role.to_owned(),
            factors: factors.iter().map(|factor| (*factor).to_owned()).collect(),
            cooldown_seconds,
        }
    }

    fn change(now: OffsetDateTime, requirement: ApprovalRequirement) -> ChangeRequest {
        ChangeRequest {
            id: Uuid::now_v7(),
            tenant_id: "default".into(),
            requested_by: "maker".into(),
            client_id: None,
            action_type: "test.protected".into(),
            params: json!({}),
            preview: None,
            target_etag: None,
            justification: "test".into(),
            binding_code: "AMBER-OTTER-01".into(),
            required_approvals: requirement.required_approvals,
            eligible_role: requirement.eligible_role,
            required_factors: requirement.factors,
            cooldown_seconds: requirement.cooldown_seconds,
            status: ChangeRequestStatus::Pending,
            approver_sub: None,
            denied_reason: None,
            execution_result: None,
            error_message: None,
            created_at: now,
            expires_at: now + Duration::minutes(15),
            decided_at: None,
            executed_at: None,
        }
    }

    fn approver(sub: &str, roles: &[&str]) -> Principal {
        Principal {
            sub: sub.into(),
            email: None,
            groups: vec![],
            issuer: "test".into(),
            scopes: vec!["mcp:admin".into()],
            tenant: waygate_core::TenantId::default(),
            auth_method: AuthMethod::Oauth,
            raw_token: None,
            roles: roles.iter().map(|role| (*role).to_owned()).collect(),
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        }
    }

    fn session(principal: &Principal, assurance: SessionAssurance) -> Session {
        Session {
            principal: principal.clone(),
            csrf_token: "test-csrf".into(),
            assurance,
            exp: i64::MAX,
        }
    }

    #[test]
    fn enforceability_accepts_role_factors_and_cooldown_but_not_break_glass() {
        assert!(requirement_enforceable(&requirement(
            "security-admins",
            &["mfa", "passkey"],
            Some(300),
        )));
        assert!(!requirement_enforceable(&requirement(
            "security-admins",
            &["break_glass"],
            None,
        )));
        assert!(!requirement_enforceable(&requirement(
            " security-admins ",
            &[],
            None,
        )));
        assert!(!requirement_enforceable(&requirement(
            "security-admins",
            &[],
            Some(-1),
        )));
    }

    #[test]
    fn cooldown_must_fit_strictly_inside_request_ttl() {
        let protected = requirement(DEFAULT_ELIGIBLE_ROLE, &[], Some(300));
        assert!(requirement_fits_ttl(&protected, 301));
        assert!(!requirement_fits_ttl(&protected, 300));
        assert!(!requirement_fits_ttl(&protected, 60));
    }

    #[test]
    fn eligible_admin_proposer_can_satisfy_single_approval_requirement() {
        let now = OffsetDateTime::now_utc();
        let change = change(now, requirement(DEFAULT_ELIGIBLE_ROLE, &[], None));
        enforce_approval_requirement(&change, &approver("maker", &[]), None, now)
            .expect("an eligible admin proposer counts toward the configured quorum");
    }

    #[test]
    fn non_default_eligible_role_requires_exact_principal_role() {
        let now = OffsetDateTime::now_utc();
        let change = change(now, requirement("security-admins", &[], None));
        assert!(matches!(
            enforce_approval_requirement(&change, &approver("alice", &[]), None, now),
            Err(ApiError::ForbiddenDyn(_))
        ));
        enforce_approval_requirement(&change, &approver("alice", &["security-admins"]), None, now)
            .expect("eligible role approves");
    }

    #[test]
    fn required_factor_must_be_present_and_fresh() {
        let now = OffsetDateTime::now_utc();
        let change = change(now, requirement(DEFAULT_ELIGIBLE_ROLE, &["mfa"], None));
        let alice = approver("alice", &[]);

        assert!(matches!(
            enforce_approval_requirement(&change, &alice, None, now),
            Err(ApiError::Forbidden(_))
        ));
        let wrong = session(
            &alice,
            SessionAssurance {
                authenticated_at: Some(now.unix_timestamp()),
                factors: vec!["passkey".into()],
            },
        );
        assert!(matches!(
            enforce_approval_requirement(&change, &alice, Some(&wrong), now),
            Err(ApiError::ForbiddenDyn(_))
        ));
        let stale = session(
            &alice,
            SessionAssurance {
                authenticated_at: Some(now.unix_timestamp() - APPROVAL_FACTOR_MAX_AGE_SECONDS - 1),
                factors: vec!["mfa".into()],
            },
        );
        assert!(matches!(
            enforce_approval_requirement(&change, &alice, Some(&stale), now),
            Err(ApiError::Forbidden(_))
        ));
        let outside_range = session(
            &alice,
            SessionAssurance {
                authenticated_at: Some(i64::MIN),
                factors: vec!["mfa".into()],
            },
        );
        assert!(matches!(
            enforce_approval_requirement(&change, &alice, Some(&outside_range), now),
            Err(ApiError::Forbidden(_))
        ));
        let fresh = session(
            &alice,
            SessionAssurance {
                authenticated_at: Some(now.unix_timestamp()),
                factors: vec!["mfa".into()],
            },
        );
        enforce_approval_requirement(&change, &alice, Some(&fresh), now)
            .expect("fresh required factor approves");

        let mallory = approver("mallory", &[]);
        let borrowed = session(
            &mallory,
            SessionAssurance {
                authenticated_at: Some(now.unix_timestamp()),
                factors: vec!["mfa".into()],
            },
        );
        assert!(matches!(
            enforce_approval_requirement(&change, &alice, Some(&borrowed), now),
            Err(ApiError::Forbidden(_))
        ));
    }

    #[test]
    fn proposal_age_cooldown_blocks_then_allows_approval() {
        let now = OffsetDateTime::now_utc();
        let change = change(
            now - Duration::seconds(299),
            requirement(DEFAULT_ELIGIBLE_ROLE, &[], Some(300)),
        );
        let alice = approver("alice", &[]);
        assert!(matches!(
            enforce_approval_requirement(&change, &alice, None, now),
            Err(ApiError::Conflict(_))
        ));
        enforce_approval_requirement(&change, &alice, None, now + Duration::seconds(1))
            .expect("cooldown boundary is approvable");
    }
}
