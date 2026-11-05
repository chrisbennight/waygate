//! Federated peer gateways.

use waygate_changeset::ChangeRequest;
use waygate_federation::FederatedPeer;

use super::{change, field_change, found, param, param_id, quoted, ChangeDescription, Lookup};
use crate::state::AdminState;

const CREATE_KEYS: &[&str] = &["peer_name", "issuer", "jwks_url"];
const UPDATE_KEYS: &[&str] = &["id", "peer_name", "issuer", "jwks_url"];
const DELETE_KEYS: &[&str] = &["id"];
#[cfg(test)]
pub(super) const DECLARED: &[(&str, &[&str])] = &[
    ("peer.create", CREATE_KEYS),
    ("peer.update", UPDATE_KEYS),
    ("peer.delete", DELETE_KEYS),
];

pub(super) async fn describe(state: &AdminState, request: &ChangeRequest) -> ChangeDescription {
    let params = &request.params;
    match request.action_type.as_str() {
        "peer.create" => {
            let (Some(name), Some(issuer), Some(keys)) = (
                param(params, "peer_name"),
                param(params, "issuer"),
                param(params, "jwks_url"),
            ) else {
                return ChangeDescription::undescribed("peer.create");
            };
            let mut description = ChangeDescription::titled(
                "peer.create",
                format!("Add peer gateway {}", quoted(name)),
                params,
                CREATE_KEYS,
            );
            description.changes = vec![
                change(format!("Issuer: {}", quoted(issuer))),
                change(format!("Signing keys from: {}", quoted(keys))),
            ];
            description
        }
        "peer.update" => {
            let peer = found!(peer(state, request).await);
            let mut description = ChangeDescription::titled(
                "peer.update",
                format!("Change peer gateway {}", quoted(&peer.peer_name)),
                params,
                UPDATE_KEYS,
            );
            for (key, label, current) in [
                ("peer_name", "Name", &peer.peer_name),
                ("issuer", "Issuer", &peer.issuer),
                ("jwks_url", "Signing keys from", &peer.jwks_url),
            ] {
                if let Some(proposed) = param(params, key).filter(|value| value != current) {
                    description.changes.push(field_change(
                        label,
                        quoted(current),
                        quoted(proposed),
                    ));
                }
            }
            if description.changes.is_empty() {
                description.note = Some("The proposed values match the current ones.".into());
            }
            description
        }
        "peer.delete" => {
            let peer = found!(peer(state, request).await);
            let mut description = ChangeDescription::titled(
                "peer.delete",
                format!("Remove peer gateway {}", quoted(&peer.peer_name)),
                params,
                DELETE_KEYS,
            );
            description.changes = vec![change(format!("Issuer: {}", quoted(&peer.issuer)))];
            description
        }
        other => ChangeDescription::undescribed(other),
    }
}

/// The peer a change or removal targets.
async fn peer(state: &AdminState, request: &ChangeRequest) -> Lookup<FederatedPeer> {
    let action = request.action_type.as_str();
    let Some(id) = param_id(&request.params, "id") else {
        return Lookup::Fallback(ChangeDescription::undescribed(action));
    };
    let read = match state.federation.federated_peers.get() {
        Some(store) => Some(store.get(&request.tenant_id, id).await),
        None => None,
    };
    Lookup::from_read(action, "peer gateway", read)
}
