// Default SCIM deactivation enforcement.
//
// `principal.scim_active` is populated from the SCIM
// `active` column for principals whose `sub` matched a SCIM row.
// SCIM clients (Okta, Authentik, EntraID) flip `active` to false
// to deactivate a user — the spec's soft-delete. Without a policy
// that consumes the flag, a deactivated user's bearer continues
// to work until the IdP revokes the token, which can take TTLs of
// minutes or hours.
//
// This policy closes that gap. Two conjuncts:
//
//   - `principal.scim_present` — guard so the rule only applies
//     to SCIM-provisioned principals. A caller who isn't in the
//     SCIM tables (service-account API key, dev mode) isn't
//     affected; their access is governed by the usual role/scope
//     rules in `10-role-allow.cedar`.
//   - `!principal.scim_active` — the deactivation signal.
//
// `forbid` overrides any later `permit` per Cedar's deny-wins
// semantics, so a deactivated mcp-admin (covered by the broad
// permit in `10-role-allow.cedar`) is still denied — which is
// the right behaviour: deactivation outranks role membership.
//
// This file is the operator-editable default that makes SCIM
// deactivation actually enforce access control — the entity
// builder exposes `scim_active`, but without a consuming
// policy the attribute has no effect on access.

// `@reason` surfaces in the MCP forbidden response's
// `data.reasons` so an operator who sees a sudden flood of
// "scim deactivated" denials in the audit feed has the
// human-readable cue without needing to deduce it from
// the policy ID alone.
@id("scim-deactivated-forbid")
@layer("scim-overlay")
@description("SCIM-provisioned principals marked inactive in the directory are denied all actions until reactivated at the IdP.")
@tags("scim, deprovisioning, security")
@reason("Principal is SCIM-provisioned and has been marked inactive in the directory — reactivate at the IdP to restore access")
forbid (principal, action, resource)
when {
    principal.scim_present && !principal.scim_active
};
