//! Consent records, stored upstream sign-ins, and break-glass tokens.

use serde_json::Value;
use waygate_changeset::ChangeRequest;

use super::{
    change, found, param, param_id, param_list, quoted, quoted_list, ChangeDescription, Lookup,
};
use crate::state::AdminState;

const CONSENT_KEYS: &[&str] = &["principal_sub", "client_id"];
const SESSION_KEYS: &[&str] = &["sub", "upstream_issuer"];
const MINT_KEYS: &[&str] = &[
    "issued_to",
    "reason",
    "scope_pattern",
    "requires_amr",
    "ttl_seconds",
];
const REVOKE_KEYS: &[&str] = &["token_id"];
#[cfg(test)]
pub(super) const DECLARED: &[(&str, &[&str])] = &[
    ("oauth_consent.revoke", CONSENT_KEYS),
    ("upstream_session.revoke", SESSION_KEYS),
    ("break_glass.mint", MINT_KEYS),
    ("break_glass.revoke", REVOKE_KEYS),
];
/// Active tokens scanned to find a revocation's target; there is no lookup by id.
const TOKEN_SCAN: u32 = 500;

pub(super) async fn describe(state: &AdminState, request: &ChangeRequest) -> ChangeDescription {
    let action = request.action_type.as_str();
    let params = &request.params;
    match action {
        "oauth_consent.revoke" => {
            let (Some(subject), Some(client)) =
                (param(params, "principal_sub"), param(params, "client_id"))
            else {
                return ChangeDescription::undescribed(action);
            };
            let mut description = ChangeDescription::titled(
                action,
                format!(
                    "Revoke the consent of {} for client {}",
                    quoted(subject),
                    quoted(client)
                ),
                params,
                CONSENT_KEYS,
            );
            let read = match state.identity.consent.get() {
                Some(store) => store.find_active(&request.tenant_id, subject, client).await,
                None => return description.cannot_read("consent"),
            };
            match read {
                Ok(Some(grant)) => {
                    description.changes = vec![
                        change(format!("Scopes: {}", quoted_list(&grant.scopes))),
                        change(format!(
                            "Expires: {}",
                            grant.expires_at.map_or_else(
                                || "never".to_owned(),
                                waygate_core::fmt::format_ts_abs
                            )
                        )),
                    ];
                }
                // Revoking is idempotent, so a missing consent changes nothing.
                Ok(None) => {
                    description.note = Some(
                        "No active consent exists for this user and client, so approval \
                         changes nothing."
                            .into(),
                    );
                }
                Err(error) => {
                    tracing::warn!(error = %error, "approval card could not read the consent");
                    return description.cannot_read("consent");
                }
            }
            description
        }
        "upstream_session.revoke" => {
            let (Some(subject), Some(issuer)) =
                (param(params, "sub"), param(params, "upstream_issuer"))
            else {
                return ChangeDescription::undescribed(action);
            };
            ChangeDescription::titled(
                action,
                format!(
                    "Delete the upstream sign-in of {} with {}",
                    quoted(subject),
                    quoted(issuer)
                ),
                params,
                SESSION_KEYS,
            )
        }
        "break_glass.mint" => {
            let (Some(holder), Some(pattern), Some(ttl)) = (
                param(params, "issued_to"),
                param(params, "scope_pattern"),
                params.get("ttl_seconds").and_then(Value::as_u64),
            ) else {
                return ChangeDescription::undescribed(action);
            };
            let mut description = ChangeDescription::titled(
                action,
                format!("Issue a break-glass token to {}", quoted(holder)),
                params,
                MINT_KEYS,
            );
            description.changes = vec![
                change(format!("Tool pattern: {}", quoted(pattern))),
                change(format!("Valid for: {}", hours_or_minutes(ttl))),
            ];
            let factors = param_list(params, "requires_amr");
            if !factors.is_empty() {
                description.changes.push(change(format!(
                    "Requires sign-in with: {}",
                    quoted_list(&factors)
                )));
            }
            if let Some(reason) = param(params, "reason").filter(|reason| !reason.is_empty()) {
                description
                    .changes
                    .push(change(format!("Recorded reason: {}", quoted(reason))));
            }
            description
        }
        "break_glass.revoke" => {
            let Some(id) = param_id(params, "token_id") else {
                return ChangeDescription::undescribed(action);
            };
            let read = match state.policy.break_glass.get() {
                Some(store) => Some(store.list(&request.tenant_id, None, TOKEN_SCAN, 0).await),
                None => None,
            };
            // Absence is known only when the scan covered every token.
            let read = match read {
                Some(Ok(tokens))
                    if tokens.len() >= TOKEN_SCAN as usize
                        && !tokens.iter().any(|token| token.id == id) =>
                {
                    return ChangeDescription::undescribed(action)
                        .noted("The token is not among the newest tokens, so it cannot be shown.");
                }
                read => read.map(|listed| {
                    listed.map(|tokens| tokens.into_iter().find(|token| token.id == id))
                }),
            };
            let token = found!(Lookup::from_read(action, "break-glass token", read));
            let mut description = ChangeDescription::titled(
                action,
                format!(
                    "Revoke the break-glass token of {}",
                    quoted(&token.issued_to)
                ),
                params,
                REVOKE_KEYS,
            );
            description.changes = vec![
                change(format!("Tool pattern: {}", quoted(&token.scope_pattern))),
                change(format!(
                    "Expires: {}",
                    waygate_core::fmt::format_ts_abs(token.expires_at)
                )),
            ];
            if !token.requires_amr.is_empty() {
                description.changes.push(change(format!(
                    "Requires sign-in with: {}",
                    quoted_list(&token.requires_amr)
                )));
            }
            if !token.reason.is_empty() {
                description.changes.push(change(format!(
                    "Recorded reason: {}",
                    quoted(&token.reason)
                )));
            }
            if token.used_at.is_some() {
                description.note = Some("The token was already used.".into());
            }
            description
        }
        other => ChangeDescription::undescribed(other),
    }
}

fn hours_or_minutes(seconds: u64) -> String {
    let plural =
        |count: u64, unit: &str| format!("{count} {unit}{}", if count == 1 { "" } else { "s" });
    if seconds >= 3_600 && seconds.is_multiple_of(3_600) {
        plural(seconds / 3_600, "hour")
    } else if seconds >= 60 && seconds.is_multiple_of(60) {
        plural(seconds / 60, "minute")
    } else {
        plural(seconds, "second")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_lifetimes_use_the_largest_exact_unit() {
        assert_eq!(hours_or_minutes(3_600), "1 hour");
        assert_eq!(hours_or_minutes(5_400), "90 minutes");
        assert_eq!(hours_or_minutes(45), "45 seconds");
    }
}
