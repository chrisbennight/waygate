//! RBAC role/assignment change-executors — split from `change_executor.rs`.
//! Child module: shared helpers (`map_core_error`,
//! `etag_of`, ...) resolve via `use super::*;`.

use super::*;
use serde::Serialize;
use time::OffsetDateTime;

/// `rbac.role.create` proposes a new RBAC role. Params mirror
/// [`crate::rbac::CreateRoleRequest`]; the executor runs the shared
/// `create_role_core`, so role-input validation, the per-tenant name
/// collision, the resolver-cache invalidation, and the fail-closed audit are
/// identical to the direct-admin path.
pub(super) struct RbacRoleCreateExecutor;

#[async_trait]
impl ActionExecutor for RbacRoleCreateExecutor {
    fn action_type(&self) -> &'static str {
        "rbac.role.create"
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let req: CreateRoleRequest = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        // Validate-before-irreversible: a proposed role may not grant
        // control-plane authority (mcp:admin / mcp:propose / scim:write), or
        // an mcp:propose maker could escalate via a single-approval role grant.
        reject_privileged_role_scopes(&req.scopes)?;
        let role = create_role_core(
            state,
            tenant_id,
            Some(actor),
            &req.name,
            req.description.as_deref(),
            &req.scopes,
        )
        .await
        .map_err(map_core_error)?;
        Ok(ExecOutcome::result(serde_json::json!({
            "role_id": role.id,
            "name": role.name,
            "scopes": role.scopes,
        })))
    }
}

// ---- rbac.role.update ----

/// Params for `rbac.role.update`: the target id plus the authoritative
/// replacement fields (`name` + `scopes`), mirroring
/// [`crate::rbac::UpdateRoleRequest`] (a role update is a full replacement,
/// not a partial patch, so `name` is required).
#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct RbacRoleUpdateParams {
    pub(super) id: Uuid,
    pub(super) name: String,
    #[serde(default)]
    pub(super) description: Option<String>,
    #[serde(default)]
    pub(super) scopes: Vec<String>,
}

pub(super) struct RbacRoleUpdateExecutor;

#[async_trait]
impl ActionExecutor for RbacRoleUpdateExecutor {
    fn action_type(&self) -> &'static str {
        "rbac.role.update"
    }

    async fn capture_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        _actor: &Principal,
        params: &Value,
    ) -> Result<Option<String>, ExecError> {
        // Fingerprint the target role's CURRENT name + description + scopes —
        // the FULL set `update_role_core` replaces (it's a full replacement, not
        // a patch: name, description, AND scopes). Omitting
        // description would let a description-only out-of-band edit pass the
        // guard and be clobbered by the approved stale update. Scopes are sorted
        // so a pure reorder isn't a false change. If an operator edits ANY of
        // these between propose and approve, the token shifts and the approved
        // replacement is refused.
        let p: RbacRoleUpdateParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let Some(store) = state.identity.rbac.get() else {
            return Ok(None);
        };
        let role = store
            .get_role(tenant_id, p.id)
            .await
            .map_err(|e| ExecError::Store(format!("rbac get_role: {e}")))?;
        Ok(role.map(|r| {
            let mut scopes = r.scopes.clone();
            scopes.sort();
            etag_of(&serde_json::json!({
                "name": r.name,
                "description": r.description,
                "scopes": scopes,
            }))
        }))
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let p: RbacRoleUpdateParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        // Validate-before-irreversible: refuse a replacement scope set that
        // includes control-plane authority — otherwise a maker could queue an
        // innocuous-looking update that grants mcp:admin/mcp:propose to an
        // already-assigned role (privilege escalation past one approval).
        reject_privileged_role_scopes(&p.scopes)?;
        // `Ok(None)` ⇒ no such role in this tenant (deleted between propose and
        // approve) — a precondition failure.
        let role = update_role_core(
            state,
            tenant_id,
            Some(actor),
            p.id,
            &p.name,
            p.description.as_deref(),
            &p.scopes,
        )
        .await
        .map_err(map_core_error)?
        .ok_or_else(|| {
            ExecError::Precondition(format!("role {} not found in this tenant", p.id))
        })?;
        Ok(ExecOutcome::result(serde_json::json!({
            "role_id": role.id,
            "name": role.name,
            "scopes": role.scopes,
        })))
    }
}

// ---- rbac.role.delete ----

/// Params for `rbac.role.delete`: the target role id. Tenant-scoped through
/// the change request's `tenant_id` — `delete_role_core` only deletes a role
/// belonging to that tenant, so a maker cannot reach another tenant's roles by
/// id. Completes the `rbac.role.{create,update,delete}` triad.
#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct RbacRoleDeleteParams {
    pub(super) id: Uuid,
}

pub(super) struct RbacRoleDeleteExecutor;

#[async_trait]
impl ActionExecutor for RbacRoleDeleteExecutor {
    fn action_type(&self) -> &'static str {
        "rbac.role.delete"
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let p: RbacRoleDeleteParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        // Validate-before-irreversible: a role carrying a control-plane
        // scope (mcp:admin / mcp:propose / scim:write)
        // defines the approver / maker / provisioning set, so DELETING it is a
        // protected **approver-set change** — the same protected/meta class that
        // bars *granting* those scopes through the propose path
        // (`reject_privileged_role_scopes` on create/update; see
        // docs/agents/hitl-control-plane.md). Removing it grants nothing, but it
        // manipulates who may approve/propose/provision, which the doctrine
        // holds is not agent-proposable. Prefetch the target and refuse BEFORE
        // the irreversible delete, so the change can never persist even if a
        // human approves it. An operator may still delete such a role via the
        // direct admin API. (Guarding the target's scopes mirrors how
        // create/update guard the proposed scopes — the executor adds the
        // propose-only guard; `delete_role_core` stays scope-agnostic so the
        // direct-admin path is unchanged.) A `None` here is the target-gone
        // precondition, identical to the `Ok(false)` path below.
        let store = super::cap(&state.identity.rbac)?;
        let role = store
            .get_role(tenant_id, p.id)
            .await
            .map_err(|e| ExecError::Store(format!("rbac get_role: {e}")))?
            .ok_or_else(|| {
                ExecError::Precondition(format!("role {} not found in this tenant", p.id))
            })?;
        if let Some(bad) = role
            .scopes
            .iter()
            .find(|s| PRIVILEGED_ROLE_SCOPES.contains(&s.as_str()))
        {
            return Err(ExecError::BadParams(format!(
                "role {} carries control-plane scope {bad:?}; deleting an \
                 approver/maker/provisioning role is a protected approver-set change and cannot be \
                 done through the propose path — an operator must delete it via the direct admin API",
                p.id
            )));
        }
        // Reuse the same core the DELETE handler and dashboard row-delete call:
        // it prefetches for the audit reason, deletes (assignments + mappings
        // cascade by FK), invalidates the resolver cache, and records the
        // fail-closed `rbac.delete_role` AdminMutation — so the propose path and
        // the direct-admin path produce identical audit. `Ok(false)` ⇒ no such
        // role in this tenant (already deleted between propose and approve, or
        // it never existed / belongs to another tenant) — a precondition
        // failure that marks the change `failed`, not a phantom success.
        let deleted = delete_role_core(state, tenant_id, Some(actor), p.id)
            .await
            .map_err(map_core_error)?;
        if !deleted {
            return Err(ExecError::Precondition(format!(
                "role {} not found in this tenant",
                p.id
            )));
        }
        Ok(ExecOutcome::result(serde_json::json!({
            "role_id": p.id,
            "deleted": true,
        })))
    }
}

// ---- direct and group role membership ----

/// Control-plane membership changes retain one eligible-admin approval and a
/// five-minute review interval. Authentication method policy belongs to the IdP, so this
/// requirement does not add a gateway-enforced MFA factor.
fn privileged_membership_requirement() -> ApprovalRequirement {
    ApprovalRequirement {
        required_approvals: 1,
        eligible_role: DEFAULT_ELIGIBLE_ROLE.into(),
        factors: Vec::new(),
        cooldown_seconds: Some(300),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MembershipClass {
    Ordinary,
    Privileged,
}

impl MembershipClass {
    fn requirement(self) -> ApprovalRequirement {
        match self {
            Self::Ordinary => ApprovalRequirement::single(DEFAULT_ELIGIBLE_ROLE),
            Self::Privileged => privileged_membership_requirement(),
        }
    }

    fn assignment_grant_action(self) -> &'static str {
        match self {
            Self::Ordinary => "rbac.assignment.grant",
            Self::Privileged => "rbac.assignment.grant_privileged",
        }
    }

    fn assignment_revoke_action(self) -> &'static str {
        match self {
            Self::Ordinary => "rbac.assignment.revoke",
            Self::Privileged => "rbac.assignment.revoke_privileged",
        }
    }

    fn group_grant_action(self) -> &'static str {
        match self {
            Self::Ordinary => "rbac.group_mapping.grant",
            Self::Privileged => "rbac.group_mapping.grant_privileged",
        }
    }

    fn group_revoke_action(self) -> &'static str {
        match self {
            Self::Ordinary => "rbac.group_mapping.revoke",
            Self::Privileged => "rbac.group_mapping.revoke_privileged",
        }
    }
}

fn role_is_privileged(role: &waygate_rbac::Role) -> bool {
    role.scopes
        .iter()
        .any(|scope| PRIVILEGED_ROLE_SCOPES.contains(&scope.as_str()))
}

fn ensure_membership_class(
    role: &waygate_rbac::Role,
    expected: MembershipClass,
    ordinary_action: &str,
    privileged_action: &str,
) -> Result<(), ExecError> {
    match (role_is_privileged(role), expected) {
        (false, MembershipClass::Ordinary) | (true, MembershipClass::Privileged) => Ok(()),
        (true, MembershipClass::Ordinary) => Err(ExecError::BadParams(format!(
            "role {} grants control-plane authority; use action {privileged_action:?} so the \
             protected approval bar is frozen onto the request",
            role.id
        ))),
        (false, MembershipClass::Privileged) => Err(ExecError::BadParams(format!(
            "role {} does not grant control-plane authority; use action {ordinary_action:?}",
            role.id
        ))),
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum MembershipWitness {
    Role {
        role_id: Uuid,
        #[serde(with = "time::serde::rfc3339")]
        role_updated_at: OffsetDateTime,
    },
    Assignment {
        assignment_id: Uuid,
        role_id: Uuid,
        #[serde(with = "time::serde::rfc3339")]
        role_updated_at: OffsetDateTime,
    },
    GroupMapping {
        group_id: Uuid,
        role_id: Uuid,
        #[serde(with = "time::serde::rfc3339")]
        mapping_created_at: OffsetDateTime,
        #[serde(with = "time::serde::rfc3339")]
        role_updated_at: OffsetDateTime,
    },
}

fn witness_token(witness: &MembershipWitness) -> Result<String, ExecError> {
    serde_json::to_string(witness)
        .map_err(|e| ExecError::Store(format!("serialize RBAC membership witness: {e}")))
}

fn parse_witness(token: Option<&str>) -> Result<MembershipWitness, ExecError> {
    let token = token.ok_or_else(|| {
        ExecError::Precondition("required RBAC membership target witness is missing".into())
    })?;
    serde_json::from_str(token)
        .map_err(|e| ExecError::Precondition(format!("invalid RBAC membership witness: {e}")))
}

async fn role_for_class(
    state: &Arc<AdminState>,
    tenant_id: &str,
    role_id: Uuid,
    class: MembershipClass,
    ordinary_action: &str,
    privileged_action: &str,
) -> Result<waygate_rbac::Role, ExecError> {
    let store = super::cap(&state.identity.rbac)?;
    let role = store
        .get_role(tenant_id, role_id)
        .await
        .map_err(|e| ExecError::Store(format!("rbac get_role: {e}")))?
        .ok_or_else(|| {
            ExecError::Precondition(format!("role {role_id} not found in this tenant"))
        })?;
    ensure_membership_class(&role, class, ordinary_action, privileged_action)?;
    Ok(role)
}

async fn require_scim_group(
    state: &Arc<AdminState>,
    tenant_id: &str,
    group_id: Uuid,
) -> Result<(), ExecError> {
    let store = super::cap(&state.identity.groups)?;
    let group = store
        .list_with_usage(tenant_id)
        .await
        .map_err(|e| ExecError::Store(format!("list groups for RBAC mapping: {e}")))?
        .into_iter()
        .find(|group| group.id == group_id)
        .ok_or_else(|| {
            ExecError::Precondition(format!("group {group_id} not found in this tenant"))
        })?;
    if group.source != "scim" {
        return Err(ExecError::BadParams(format!(
            "group {group_id} is local; RBAC group mappings require a SCIM-provisioned group \
             because API-key catalog groups are Cedar facts, not identity membership"
        )));
    }
    Ok(())
}

/// Params for direct role grants. Read `role_id` from `rbac_role`; the subject
/// is the exact JWT `sub` to receive the role.
#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct RbacAssignmentGrantParams {
    /// Role identifier from `read_resource(resource_type="rbac_role")`.
    role_id: Uuid,
    /// Exact identity-provider subject (`sub`) that receives the role.
    subject_sub: String,
}

pub(super) struct RbacAssignmentGrantExecutor(pub(super) MembershipClass);

#[async_trait]
impl ActionExecutor for RbacAssignmentGrantExecutor {
    fn action_type(&self) -> &'static str {
        self.0.assignment_grant_action()
    }

    fn requirement(&self) -> ApprovalRequirement {
        self.0.requirement()
    }

    fn requires_target_etag(&self) -> bool {
        true
    }

    async fn capture_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        _actor: &Principal,
        params: &Value,
    ) -> Result<Option<String>, ExecError> {
        let p: RbacAssignmentGrantParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let role = role_for_class(
            state,
            tenant_id,
            p.role_id,
            self.0,
            MembershipClass::Ordinary.assignment_grant_action(),
            MembershipClass::Privileged.assignment_grant_action(),
        )
        .await?;
        Ok(Some(witness_token(&MembershipWitness::Role {
            role_id: role.id,
            role_updated_at: role.updated_at,
        })?))
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let witness = self.capture_etag(state, tenant_id, actor, params).await?;
        self.execute_with_target_etag(state, tenant_id, actor, params, witness.as_deref())
            .await
    }

    async fn execute_with_target_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
        target_etag: Option<&str>,
    ) -> Result<ExecOutcome, ExecError> {
        let p: RbacAssignmentGrantParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let MembershipWitness::Role {
            role_id,
            role_updated_at,
        } = parse_witness(target_etag)?
        else {
            return Err(ExecError::Precondition(
                "RBAC assignment grant witness has the wrong shape".into(),
            ));
        };
        if role_id != p.role_id {
            return Err(ExecError::Precondition(
                "RBAC assignment grant witness targets another role".into(),
            ));
        }
        let assignment = create_assignment_if_role_version_core(
            state,
            tenant_id,
            Some(actor),
            p.role_id,
            &p.subject_sub,
            role_updated_at,
        )
        .await
        .map_err(map_core_error)?
        .ok_or_else(|| {
            ExecError::Precondition(
                "role changed or disappeared before the assignment grant".into(),
            )
        })?;
        Ok(ExecOutcome::result(serde_json::json!({
            "assignment_id": assignment.id,
            "role_id": assignment.role_id,
            "subject_sub": assignment.subject_sub,
        })))
    }
}

/// Params for direct-role revocation. The assignment id comes from the
/// tenant's `rbac_assignment` resource.
#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct RbacAssignmentRevokeParams {
    /// Assignment identifier from `read_resource(resource_type="rbac_assignment")`.
    id: Uuid,
}

pub(super) struct RbacAssignmentRevokeExecutor(pub(super) MembershipClass);

#[async_trait]
impl ActionExecutor for RbacAssignmentRevokeExecutor {
    fn action_type(&self) -> &'static str {
        self.0.assignment_revoke_action()
    }

    fn requirement(&self) -> ApprovalRequirement {
        self.0.requirement()
    }

    fn requires_target_etag(&self) -> bool {
        true
    }

    async fn capture_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        _actor: &Principal,
        params: &Value,
    ) -> Result<Option<String>, ExecError> {
        let p: RbacAssignmentRevokeParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let store = super::cap(&state.identity.rbac)?;
        let assignment = store
            .get_assignment(tenant_id, p.id)
            .await
            .map_err(|e| ExecError::Store(format!("rbac get_assignment: {e}")))?
            .ok_or_else(|| {
                ExecError::Precondition(format!("assignment {} not found in this tenant", p.id))
            })?;
        let role = role_for_class(
            state,
            tenant_id,
            assignment.role_id,
            self.0,
            MembershipClass::Ordinary.assignment_revoke_action(),
            MembershipClass::Privileged.assignment_revoke_action(),
        )
        .await?;
        Ok(Some(witness_token(&MembershipWitness::Assignment {
            assignment_id: assignment.id,
            role_id: role.id,
            role_updated_at: role.updated_at,
        })?))
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let witness = self.capture_etag(state, tenant_id, actor, params).await?;
        self.execute_with_target_etag(state, tenant_id, actor, params, witness.as_deref())
            .await
    }

    async fn execute_with_target_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
        target_etag: Option<&str>,
    ) -> Result<ExecOutcome, ExecError> {
        let p: RbacAssignmentRevokeParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let MembershipWitness::Assignment {
            assignment_id,
            role_id,
            role_updated_at,
        } = parse_witness(target_etag)?
        else {
            return Err(ExecError::Precondition(
                "RBAC assignment revoke witness has the wrong shape".into(),
            ));
        };
        if assignment_id != p.id {
            return Err(ExecError::Precondition(
                "RBAC assignment revoke witness targets another assignment".into(),
            ));
        }
        delete_assignment_if_role_version_core(
            state,
            tenant_id,
            Some(actor),
            p.id,
            role_id,
            role_updated_at,
        )
        .await
        .map_err(map_core_error)?
        .ok_or_else(|| {
            ExecError::Precondition("assignment or its role changed before the revocation".into())
        })?;
        Ok(ExecOutcome::result(serde_json::json!({
            "assignment_id": p.id,
            "revoked": true,
        })))
    }
}

/// Params for granting a role through a SCIM-provisioned group.
#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct RbacGroupMappingParams {
    /// Group identifier from `read_resource(resource_type="group")`.
    group_id: Uuid,
    /// Role identifier from `read_resource(resource_type="rbac_role")`.
    role_id: Uuid,
}

pub(super) struct RbacGroupMappingGrantExecutor(pub(super) MembershipClass);

#[async_trait]
impl ActionExecutor for RbacGroupMappingGrantExecutor {
    fn action_type(&self) -> &'static str {
        self.0.group_grant_action()
    }

    fn requirement(&self) -> ApprovalRequirement {
        self.0.requirement()
    }

    fn requires_target_etag(&self) -> bool {
        true
    }

    async fn capture_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        _actor: &Principal,
        params: &Value,
    ) -> Result<Option<String>, ExecError> {
        let p: RbacGroupMappingParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        require_scim_group(state, tenant_id, p.group_id).await?;
        let role = role_for_class(
            state,
            tenant_id,
            p.role_id,
            self.0,
            MembershipClass::Ordinary.group_grant_action(),
            MembershipClass::Privileged.group_grant_action(),
        )
        .await?;
        Ok(Some(witness_token(&MembershipWitness::Role {
            role_id: role.id,
            role_updated_at: role.updated_at,
        })?))
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let witness = self.capture_etag(state, tenant_id, actor, params).await?;
        self.execute_with_target_etag(state, tenant_id, actor, params, witness.as_deref())
            .await
    }

    async fn execute_with_target_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
        target_etag: Option<&str>,
    ) -> Result<ExecOutcome, ExecError> {
        let p: RbacGroupMappingParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let MembershipWitness::Role {
            role_id,
            role_updated_at,
        } = parse_witness(target_etag)?
        else {
            return Err(ExecError::Precondition(
                "RBAC group-mapping grant witness has the wrong shape".into(),
            ));
        };
        if role_id != p.role_id {
            return Err(ExecError::Precondition(
                "RBAC group-mapping grant witness targets another role".into(),
            ));
        }
        let mapping = create_group_mapping_if_role_version_core(
            state,
            tenant_id,
            Some(actor),
            p.group_id,
            p.role_id,
            role_updated_at,
        )
        .await
        .map_err(map_core_error)?
        .ok_or_else(|| {
            ExecError::Precondition(
                "group or role changed or disappeared before the mapping grant".into(),
            )
        })?;
        Ok(ExecOutcome::result(serde_json::json!({
            "group_id": mapping.group_id,
            "role_id": mapping.role_id,
            "granted": true,
        })))
    }
}

pub(super) struct RbacGroupMappingRevokeExecutor(pub(super) MembershipClass);

#[async_trait]
impl ActionExecutor for RbacGroupMappingRevokeExecutor {
    fn action_type(&self) -> &'static str {
        self.0.group_revoke_action()
    }

    fn requirement(&self) -> ApprovalRequirement {
        self.0.requirement()
    }

    fn requires_target_etag(&self) -> bool {
        true
    }

    async fn capture_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        _actor: &Principal,
        params: &Value,
    ) -> Result<Option<String>, ExecError> {
        let p: RbacGroupMappingParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        require_scim_group(state, tenant_id, p.group_id).await?;
        let store = super::cap(&state.identity.rbac)?;
        let mapping = store
            .list_group_mappings(tenant_id, Some(p.role_id), Some(p.group_id))
            .await
            .map_err(|e| ExecError::Store(format!("rbac list_group_mappings: {e}")))?
            .into_iter()
            .next()
            .ok_or_else(|| {
                ExecError::Precondition(format!(
                    "group mapping {}/{} not found in this tenant",
                    p.group_id, p.role_id
                ))
            })?;
        let role = role_for_class(
            state,
            tenant_id,
            p.role_id,
            self.0,
            MembershipClass::Ordinary.group_revoke_action(),
            MembershipClass::Privileged.group_revoke_action(),
        )
        .await?;
        Ok(Some(witness_token(&MembershipWitness::GroupMapping {
            group_id: mapping.group_id,
            role_id: mapping.role_id,
            mapping_created_at: mapping.created_at,
            role_updated_at: role.updated_at,
        })?))
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let witness = self.capture_etag(state, tenant_id, actor, params).await?;
        self.execute_with_target_etag(state, tenant_id, actor, params, witness.as_deref())
            .await
    }

    async fn execute_with_target_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
        target_etag: Option<&str>,
    ) -> Result<ExecOutcome, ExecError> {
        let p: RbacGroupMappingParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let MembershipWitness::GroupMapping {
            group_id,
            role_id,
            mapping_created_at,
            role_updated_at,
        } = parse_witness(target_etag)?
        else {
            return Err(ExecError::Precondition(
                "RBAC group-mapping revoke witness has the wrong shape".into(),
            ));
        };
        if group_id != p.group_id || role_id != p.role_id {
            return Err(ExecError::Precondition(
                "RBAC group-mapping revoke witness targets another mapping".into(),
            ));
        }
        delete_group_mapping_if_versions_core(
            state,
            tenant_id,
            Some(actor),
            p.group_id,
            p.role_id,
            mapping_created_at,
            role_updated_at,
        )
        .await
        .map_err(map_core_error)?
        .ok_or_else(|| {
            ExecError::Precondition(
                "group mapping or its role changed before the revocation".into(),
            )
        })?;
        Ok(ExecOutcome::result(serde_json::json!({
            "group_id": p.group_id,
            "role_id": p.role_id,
            "revoked": true,
        })))
    }
}

// ---- tenant.update ----
